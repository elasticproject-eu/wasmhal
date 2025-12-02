# ELASTIC TEE HAL - WIT Interface Definitions

This directory contains two approaches to the WIT interface definitions:

## Current Structure

### `world.wit` (Monolithic - Backward Compatible)
The original single-file approach with one world exporting all interfaces. Use this for:
- Existing projects and backward compatibility
- Quick prototyping with all features
- Full HAL implementations

### `../wit-modular/` (Modular - Recommended for New Projects)
Refactored into separate, composable interface packages. Use this for:
- New development and incremental implementation
- Selective feature composition
- Independent interface versioning
- Wasm implementations of individual interfaces
- Better alignment with WASI composition patterns

## Migration Guide

If you're starting a new project, we recommend using the modular interfaces in `../wit-modular/`. The modular approach provides:

1. **Independent Development** - Implement one interface at a time
2. **Selective Composition** - Only include what you need
3. **No Stubbing Required** - No need to stub unused interfaces
4. **WASI Alignment** - Follows modern WASI proposals

See `../wit-modular/README.md` for detailed documentation on the modular approach.

## Future Direction

The modular approach is the recommended path forward. The monolithic `world.wit` will be maintained for backward compatibility but new features and improvements will focus on the modular structure.
