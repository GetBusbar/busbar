// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Image-generation IR. Cross-protocol across OpenAI, Gemini, Bedrock.
//! ONE operation with an `op` discriminant (Generate/Edit/Variation) — edit/variation are not separate
//! ops; an unsupported `(op, model)` pair is a sub-op 404. Split request/response per.
//!
//! Losslessness: the three provider geometry conventions (explicit W×H, `aspect_ratio` string, size
//! `tier`) are PARALLEL optionals — never collapsed. Response images are additive [`ImageOutput`]
//! (b64 AND url may coexist). Common cross-provider fields are typed; provider-unique knobs (Titan
//! `controlMode`, SDXL `sampler`/`clip_guidance_preset`, per-prompt weights…) ride source-scoped
//! `extra`. Billing: `Tokens` for gpt-image-1/Gemini, else `Billing::Images` (per-image, no usage body).

use crate::billing::{Billing, TokenUsage};
use crate::lossless::SourceScopedExtra;
use crate::media::ImageOutput;

/// Which image operation. Support is non-uniform per model → unsupported `(op, model)` = 404.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ImageOp {
    #[default]
    Generate,
    /// No 1.5.0 egress writer emits anything but `/v1/images/generations`, so nothing constructs
    /// this variant yet; kept because the superset IR must be able to express an edit request.
    #[allow(dead_code)]
    Edit,
    /// No 1.5.0 egress writer emits anything but `/v1/images/generations`, so nothing constructs
    /// this variant in production yet; kept for the same reason as `Edit`.
    #[cfg_attr(not(test), allow(dead_code))]
    Variation,
}

/// Explicit pixel geometry (OpenAI string `"1024x1024"`/`"auto"`, Titan/SDXL width/height ints).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageSize {
    Wh { width: u32, height: u32 },
    Auto,
}

/// Image request IR — superset of common cross-provider fields; exotic knobs ride `extra`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ImageReq {
    pub op: ImageOp,
    pub model: String,
    pub prompt: Option<String>, // Option: dall-e-2 variations carry no prompt
    pub negative_prompt: Option<String>,
    pub n: Option<u32>,
    // --- geometry: three mutually-exclusive provider conventions, kept parallel (lossless) ---
    pub size: Option<ImageSize>,         // OpenAI/Titan/SDXL
    pub aspect_ratio: Option<String>,    // Google, Stable Image ("16:9")
    pub image_size_tier: Option<String>, // Imagen ("1K"/"2K")
    // --- quality / style / output ---
    pub quality: Option<String>, // standard|hd|low|medium|high|premium|auto
    pub style: Option<String>,   // dall-e-3 vivid/natural; SDXL style_preset
    pub response_format: Option<String>, // url|b64_json (only dall-e honors; else b64)
    pub output_format: Option<String>, // png|jpeg|webp
    pub output_compression: Option<u8>,
    // --- sampling / determinism ---
    pub seed: Option<u64>,
    pub guidance_scale: Option<f32>, // guidanceScale / cfg_scale / cfgScale
    pub steps: Option<u32>,          // SDXL
    pub background: Option<String>,  // transparent|opaque|auto (gpt-image-1)
    // --- edit / img2img inputs ---
    pub input_images: Vec<String>, // b64 / data-URI (edits up to 16; variation 1)
    pub mask: Option<String>,      // b64 mask (dall-e-2 edits; Titan)
    pub mask_prompt: Option<String>, // Titan text mask
    pub strength: Option<f32>,     // img2img / similarityStrength
    // --- safety / provenance / misc ---
    pub person_generation: Option<String>,
    pub moderation: Option<String>,
    pub add_watermark: Option<bool>,
    pub output_uri: Option<String>, // Google storageUri (gs://)
    pub user: Option<String>,
    /// SDXL weighted prompts; if non-empty, overrides `prompt`.
    pub weighted_prompts: Vec<(String, f32)>,
    pub extra: SourceScopedExtra,
}

/// THE IMAGE FAMILY'S WALK — this IR's answer to [`crate::ir::facts::IrFacts`]. Unlike an enum, a
/// struct has no exhaustiveness check on its fields, so EVERY caller-text field is enumerated here by
/// hand (MAJOR-6) and the `image_projection_covers_every_text_field` forcing-function test fails
/// loudly if a new `String` field is added without a projection decision. Screenable text →
/// [`crate::ir::facts::ContentItem::Text`]: `prompt`, `negative_prompt`, `mask_prompt`, and each
/// `weighted_prompts` string (SDXL, which override `prompt`). Binary edit inputs →
/// [`crate::ir::facts::ContentItem::Opaque`] (present-but-unscreenable, mirroring chat's image
/// opacity): each `input_images` entry and the `mask`. The geometry / quality / sampling / provenance
/// knobs are enum/numeric roles, not caller free-text, and stay out.
impl crate::ir::facts::IrFacts for ImageReq {
    fn verb(&self) -> crate::operation::Operation {
        crate::operation::Operation::IMAGE
    }

    fn wants_stream(&self) -> bool {
        false
    }

    fn end_user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    fn shape(&self) -> crate::ir::facts::Shape {
        let items = crate::ir::facts::IrFacts::content(self);
        let (text_chars, system_chars) = crate::ir::facts::Shape::counts_over(&items);
        crate::ir::facts::Shape {
            turn_count: 1,
            has_tools: false,
            tool_count: 0,
            text_chars,
            system_chars,
            max_tokens: None,
        }
    }

    fn content(&self) -> Vec<crate::ir::facts::ContentItem<'_>> {
        use crate::ir::facts::{ContentItem, Slot, OPAQUE_CONTENT_MARKER};
        use std::borrow::Cow;
        let mut out = Vec::new();
        if let Some(p) = &self.prompt {
            out.push(ContentItem::Text {
                author: "user",
                slot: Slot::Turn(0),
                text: Cow::Borrowed(p.as_str()),
            });
        }
        if let Some(p) = &self.negative_prompt {
            out.push(ContentItem::Text {
                author: "user",
                slot: Slot::Turn(0),
                text: Cow::Borrowed(p.as_str()),
            });
        }
        if let Some(p) = &self.mask_prompt {
            out.push(ContentItem::Text {
                author: "user",
                slot: Slot::Turn(0),
                text: Cow::Borrowed(p.as_str()),
            });
        }
        for (p, _weight) in &self.weighted_prompts {
            out.push(ContentItem::Text {
                author: "user",
                slot: Slot::Turn(0),
                text: Cow::Borrowed(p.as_str()),
            });
        }
        for _ in &self.input_images {
            out.push(ContentItem::Opaque {
                author: "user",
                slot: Slot::Turn(0),
                label: "image",
                marker: OPAQUE_CONTENT_MARKER,
            });
        }
        if self.mask.is_some() {
            out.push(ContentItem::Opaque {
                author: "user",
                slot: Slot::Turn(0),
                label: "mask",
                marker: OPAQUE_CONTENT_MARKER,
            });
        }
        out
    }
}

/// For per-image providers that return no usage object — the gateway records what it billed from
/// request params (priced by 1.3). Complements `usage` (token-metered models).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CostBasis {
    pub count: u32,
    pub size: Option<String>,
    pub quality: Option<String>,
}

/// Image response IR.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ImageResp {
    pub created: Option<u64>,
    pub images: Vec<ImageOutput>, // additive per image (b64 AND url may coexist)
    pub usage: Option<TokenUsage>, // gpt-image-1, Gemini (token-metered)
    pub cost_basis: Option<CostBasis>, // per-image providers (dall-e/Imagen/Titan/SDXL)
    pub warnings: Vec<String>,    // raiFilteredReason, finish_reasons, moderation notes
    pub extra: SourceScopedExtra,
}

impl ImageResp {
    /// Billing projection: token usage when present (gpt-image-1/Gemini); else per-image `Images`.
    pub fn billing(&self) -> Option<Billing> {
        if let Some(u) = &self.usage {
            Some(Billing::Tokens(u.clone()))
        } else {
            self.cost_basis.as_ref().map(|cb| Billing::Images {
                count: cb.count,
                size: cb.size.clone(),
                quality: cb.quality.clone(),
            })
        }
    }
}

#[cfg(test)]
#[path = "tests/image_tests.rs"]
mod tests;
