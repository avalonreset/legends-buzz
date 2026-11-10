# Knowledge pack: attach and update

`legends-buzz` ships an attachable Empire knowledge pack. It is a versioned reference shelf, not a vault and not a standalone skill.

## Pack identity

- Manifest: `knowledge/buzz/pack.json`
- Schema: `legends.knowledge-pack/v1`
- Id: `buzz`
- Module: `legends-buzz`
- Version: `0.1.0`
- Entrypoint: `index.md`
- Suggested home: `wiki/library/legends-buzz/buzz`
- Ontology kind: `library`
- Files: declared Markdown under sibling `vault/`, each pinned by SHA-256

## Ownership

| Material | Location | Update behavior |
|---|---|---|
| Released knowledge | Installed module `knowledge/buzz/vault/` | Updated with the module |
| Attached reference snapshot | Selected Empire shelf `reference/` | Updated only when the last shipped bytes are unchanged |
| User knowledge | Shelf `index.md` plus user project, relay, and receipt notes | Never overwritten by pack updates |

## Attach or update

1. Resolve the manifest path in machine-readable form:

   ```bash
   legends-buzz resources
   ```

   Read `pack_manifest` (absolute path to `pack.json`) and confirm `complete` is `true`.
2. Preview attachment into an Empire vault using `legends-empire`:

   ```bash
   cto-legends run legends-empire -- knowledge attach /abs/path/to/pack.json --vault /abs/path/to/Empire --operation-id attach-buzz-001 --generated-at 2026-11-10T12:00:00Z
   ```

3. Review the proposed transaction and apply with `--apply --approved-plan-sha256 <reviewed-hash>` when authorized.

## Private work templates

The pack includes reusable templates under `vault/templates/`:
- [private-operation-receipt.md](../templates/private-operation-receipt.md): dated operational evidence for Buzz channel, roster, or agent changes.
- [relay-upgrade-receipt.md](../templates/relay-upgrade-receipt.md): 8-gate isolated clone migration and `@sha256` digest promotion receipt.
- [canary-verification-receipt.md](../templates/canary-verification-receipt.md): proof of disposable message send, readback, reaction add/remove, and cleanup deletion.
