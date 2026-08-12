#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""An A2A agent that implements the TCK's published SUT behaviour contract.

WHY THIS EXISTS.

The A2A conformance subject leg boots busbar and points the official TCK at it. busbar is a
gateway: every task the suite sends is carried to a real backend agent and its answer carried
back. So the leg does not only measure busbar -- it measures busbar *fronting whatever agent it
was given*, and the agent it was given decides how much of busbar the suite can even reach.

Until now that agent was the pinned `a2a-go` control in `--echo` mode. Echo completes every task
in one step. A suite that cannot get a task to sit in a non-terminal state cannot test cancelling
one, resubscribing to one, reading its history, or taking a second turn on it -- so eleven MUST
requirements were being reported against busbar that busbar was never given a chance to answer.
They did not fail on busbar's conduct; they never ran.

WHAT THIS AGENT IS, AND WHY IT IS NOT A TUNED FIXTURE.

The TCK publishes a behaviour contract for the system it tests, in `docs/SUT_REQUIREMENTS.md` and
in the Gherkin feature files under `scenarios/`, which that document names as "the source of truth
for all SUT executor behavior". The contract is an in-band one: a message whose `messageId` starts
with a given prefix asks the agent for a given behaviour -- `tck-input-required` asks it to park
the task in `input-required`, `tck-artifact-data` asks it to attach a data artifact, and so on.

This file implements that contract and nothing else. Three properties keep it honest:

  * THE BEHAVIOUR IS NOT OURS TO CHOOSE. Every branch below is a transcription of a scenario the
    TCK's own authors wrote, prefix for prefix and string for string. There is no branch here that
    the published contract does not ask for, and none of them mentions, detects or accommodates
    busbar. Run this agent behind any A2A gateway, or none, and it behaves identically.
  * THE PROTOCOL IS NOT OURS EITHER. Every byte on the wire -- JSON-RPC framing, SSE, task store,
    state machine, timestamps, serialisation -- is produced by the A2A project's own Python SDK at
    the version this repository already pins as a control. What this file contributes is the
    scenario routing; it implements no protocol.
  * IT CAN STILL FAIL BUSBAR. Answering more of the contract means presenting busbar with MORE to
    get wrong, not less: artifacts with file, URL and structured-data parts, a bare Message reply
    where a Task was not created, chunked artifact appends, a task that stays open across two
    turns. Each is a fresh chance for the gateway in front of it to mistranslate, and the suite
    reports it when that happens. An agent that could not make the subject red would be worthless
    as evidence when it is green.

WHAT IT DELIBERATELY DOES NOT DO. It does not vendor the TCK's own SUT. That SUT is written
against an unreleased checkout of the A2A Python SDK (a path dependency in its `pyproject.toml`)
and does not import against any published release; and `testing/a2a-tck/LICENSING.md` records why
nothing from `a2a-tck` is copied into this repository. The contract is a document, and documents
are for implementing.

WHAT IT IS NOT ALLOWED TO REPAIR. If a backend's own serialisation is wrong, that is the
backend's record and this agent does not launder it. The scenarios below say what to do, not how
to spell it; the spelling comes from the SDK.

USAGE
  scenario_agent.py --port N [--public-url URL]
      --port         loopback port to listen on
      --public-url   the base URL to advertise in the agent card. Defaults to the listen URL.
                     Set it when something fronts this agent and the card must name the front.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os

import httpx
import uvicorn

from google.protobuf import json_format
from google.protobuf.struct_pb2 import Value
from starlette.applications import Starlette

from a2a.server.agent_execution.agent_executor import AgentExecutor
from a2a.server.agent_execution.context import RequestContext
from a2a.server.events.event_queue import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import (
    create_agent_card_routes,
    create_jsonrpc_routes,
)
from a2a.server.tasks import (
    BasePushNotificationSender,
    InMemoryPushNotificationConfigStore,
    InMemoryTaskStore,
    TaskUpdater,
)
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentProvider,
    AgentSkill,
    Part,
    Task,
    TaskState,
    TaskStatus,
)
from a2a.utils.errors import A2AError


# The JSON-RPC endpoint sits at the root because that is where the rig's registration points and
# where the pinned control served it. A card is served at the well-known path either way.
JSONRPC_URL = '/'

# `docs/SUT_REQUIREMENTS.md`: a task created by a `test-resubscribe-message-id` message must stay
# active for at least 2x TCK_STREAMING_TIMEOUT so the suite has time to resubscribe to it. The
# document names the environment variable; honour it rather than hard-coding the doubled default.
_STREAMING_TIMEOUT_S = float(os.environ.get('TCK_STREAMING_TIMEOUT', '2.0'))
_RESUBSCRIBE_HOLD_S = 2.0 * _STREAMING_TIMEOUT_S

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('a2a-scenario-agent')


class ScenarioExecutor(AgentExecutor):
    """Routes on the `messageId` prefix, exactly as the published scenarios specify.

    Order matters in one place only: `tck-artifact-file-url` and `tck-stream-artifact-*` are
    tested before their shorter siblings `tck-artifact-file` and `tck-stream-artifact` would
    swallow them. Everything else is independent.
    """

    async def execute(
        self, context: RequestContext, event_queue: EventQueue
    ) -> None:
        task_id = context.task_id
        context_id = context.context_id
        if task_id is None or context_id is None:
            return

        updater = TaskUpdater(event_queue, task_id, context_id)
        message = context.message
        if message is None:
            await updater.complete(
                updater.new_agent_message([Part(text='No message provided')])
            )
            return

        message_id = message.message_id
        logger.info('scenario dispatch for messageId %s', message_id)

        # The one scenario that produces NO task: "return a message with a text part". It is
        # tested first because opening a task for it would answer a Task where the contract, and
        # DM-MSG-001, say a bare Message.
        if message_id.startswith('tck-message-response'):
            await event_queue.enqueue_event(
                updater.new_agent_message([Part(text='Direct message response')])
            )
            return

        # Every other scenario is about a task. A first turn has to OPEN the task before any
        # status update names it; a follow-up turn must not, because the task already exists and
        # re-opening it would discard the history the multi-turn and history requirements are
        # about. This is SDK scaffolding, not a scenario decision -- the scenarios say what state
        # to leave the task in, not how a task comes into being -- and it is the idiom the SDK's
        # own sample executor uses.
        if context.current_task is None:
            await event_queue.enqueue_event(
                Task(
                    id=task_id,
                    context_id=context_id,
                    status=TaskStatus(state=TaskState.TASK_STATE_SUBMITTED),
                    history=[message],
                )
            )

        # -- streaming scenarios (scenarios/streaming.feature) ------------------------------
        if message_id.startswith('tck-stream-artifact-chunked'):
            await updater.start_work()
            await updater.add_artifact(parts=[Part(text='chunk-1 ')], append=True)
            await updater.add_artifact(
                parts=[Part(text='chunk-2')], append=True, last_chunk=True
            )
            await updater.complete()
            return

        if message_id.startswith('test-resubscribe-message-id'):
            await updater.start_work()
            await asyncio.sleep(_RESUBSCRIBE_HOLD_S)
            await updater.complete()
            return

        if message_id.startswith('tck-stream-artifact-text'):
            await updater.start_work()
            await updater.add_artifact(parts=[Part(text='Streamed text content')])
            await updater.complete()
            return

        if message_id.startswith('tck-stream-artifact-file'):
            await updater.start_work()
            await updater.add_artifact(
                parts=[
                    Part(raw=b'tck', media_type='text/plain', filename='output.txt')
                ]
            )
            await updater.complete()
            return

        if message_id.startswith('tck-stream-ordering-001'):
            await updater.start_work()
            await updater.add_artifact(parts=[Part(text='Ordered output')])
            await updater.complete()
            return

        if message_id.startswith('tck-stream-001'):
            await updater.start_work()
            await updater.add_artifact(parts=[Part(text='Stream hello from TCK')])
            await updater.complete()
            return

        if message_id.startswith('tck-stream-002'):
            await updater.complete()
            return

        if message_id.startswith('tck-stream-003'):
            await updater.start_work()
            await updater.add_artifact(parts=[Part(text='Stream task lifecycle')])
            await updater.complete()
            return

        # -- core scenarios (scenarios/core_operations.feature) -----------------------------
        if message_id.startswith('tck-artifact-file-url'):
            await updater.add_artifact(
                parts=[
                    Part(
                        url='https://example.com/output.txt',
                        media_type='text/plain',
                        filename='output.txt',
                    )
                ]
            )
            await updater.complete()
            return

        if message_id.startswith('tck-artifact-file'):
            await updater.add_artifact(
                parts=[
                    Part(raw=b'tck', media_type='text/plain', filename='output.txt')
                ]
            )
            await updater.complete()
            return

        if message_id.startswith('tck-artifact-text'):
            await updater.add_artifact(parts=[Part(text='Generated text content')])
            await updater.complete()
            return

        if message_id.startswith('tck-artifact-data'):
            await updater.add_artifact(
                parts=[
                    Part(
                        data=json_format.Parse(
                            '{"key": "value", "count": 42}', Value()
                        )
                    )
                ]
            )
            await updater.complete()
            return

        # The scenario that unblocks the eleven: park the task, do not finish it. A second turn
        # carrying the same taskId with a `tck-complete-task` id closes it, which is what the
        # multi-turn, history and push-delivery setups do.
        if message_id.startswith('tck-input-required'):
            await updater.requires_input()
            return

        if message_id.startswith('tck-complete-task'):
            await updater.complete(
                updater.new_agent_message([Part(text='Hello from TCK')])
            )
            return

        if message_id.startswith('tck-reject-task'):
            raise A2AError('rejected')

        # No prefix claimed it. The contract says "normal task processing, no special behaviour",
        # and says so out loud rather than silently echoing, so a prefix this agent has not
        # implemented is visible in the transcript instead of passing for a handled one.
        await updater.complete(
            updater.new_agent_message(
                [Part(text='Unhandled messageId prefix: ' + message_id)]
            )
        )

    async def cancel(
        self, context: RequestContext, event_queue: EventQueue
    ) -> None:
        task_id = context.task_id
        context_id = context.context_id
        if task_id is None or context_id is None:
            return
        await TaskUpdater(event_queue, task_id, context_id).cancel()


def build_card(public_url: str) -> AgentCard:
    """The card this agent publishes.

    `pushNotifications` IS TRUE, and it is true because the agent really does it: `main` gives the
    SDK's request handler a push configuration store and a webhook sender, so a config set on this
    agent is stored and a webhook is called from this process. The claim was checked before it was
    made -- a fixture that advertises a capability it does not implement is a fixture that lies to
    every suite that reads its card.

    It has to be declared rather than left off for a reason worth stating: a gateway that fronts
    this agent may serve a card derived from THIS one, in which case a capability omitted here is
    a capability the suite never asks the gateway about. Whether that derivation is right is the
    gateway's business and not this file's -- but a fixture must not be the reason a requirement
    goes untested.
    """
    return AgentCard(
        name='A2A TCK scenario agent',
        description=(
            'An A2A agent implementing the TCK SUT behaviour contract published in that '
            'suite\'s scenario feature files. Used as the backend agent in conformance rigs.'
        ),
        version='1.0.0',
        provider=AgentProvider(organization='busbar', url='https://getbusbar.com'),
        supported_interfaces=[
            AgentInterface(
                url=public_url,
                protocol_binding='JSONRPC',
                protocol_version='1.0',
            ),
        ],
        capabilities=AgentCapabilities(
            streaming=True,
            push_notifications=True,
        ),
        default_input_modes=['text'],
        default_output_modes=['text'],
        skills=[
            AgentSkill(
                id='tck-scenarios',
                name='TCK scenarios',
                description='Behaviour selected in-band by the messageId prefix.',
                tags=['tck', 'conformance'],
            ),
        ],
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--public-url', default=None)
    args = parser.parse_args()

    public_url = args.public_url or f'http://{args.host}:{args.port}/'

    card = build_card(public_url)
    # Push is implemented, not merely claimed: the SDK's own config store and webhook sender.
    push_store = InMemoryPushNotificationConfigStore()
    push_sender = BasePushNotificationSender(
        httpx_client=httpx.AsyncClient(timeout=10.0),
        config_store=push_store,
    )
    handler = DefaultRequestHandler(
        agent_executor=ScenarioExecutor(),
        task_store=InMemoryTaskStore(),
        agent_card=card,
        push_config_store=push_store,
        push_sender=push_sender,
    )

    routes = [
        # v0.3 compatibility is enabled because a client is entitled to speak either revision
        # to an agent that says it accepts both, and refusing the older one would be this
        # fixture narrowing the protocol rather than the peer being tested doing so.
        *create_jsonrpc_routes(
            request_handler=handler,
            rpc_url=JSONRPC_URL,
            enable_v0_3_compat=True,
        ),
        *create_agent_card_routes(agent_card=card),
    ]

    uvicorn.run(
        Starlette(routes=routes),
        host=args.host,
        port=args.port,
        log_level='warning',
    )


if __name__ == '__main__':
    main()
