A crate on this side of the line cannot mint a capability seal. It does not list `busbar-seal`, the
crate whose two free functions are the only constructors, so the compiler refuses the name:

```compile_fail,E0433
let _seal = busbar_seal::mint_kernel();
```

```compile_fail,E0433
let _seal = busbar_seal::mint_slot();
```

The contract re-exports the seal TYPES and nothing that builds one. A free function does not travel
with a re-exported type:

```compile_fail,E0425
let _seal = busbar_contract::caps::mint_kernel();
```

and the seal types have no public constructor and no hand-off to call:

```compile_fail,E0599
let _boxed = busbar_contract::caps::KernelSeal::deliver();
```

```compile_fail,E0599
let _boxed = busbar_contract::caps::SlotSeal::deliver();
```
