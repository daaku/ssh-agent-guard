# ssh-agent-guard

An ssh-agent proxy. When the real agent answers `REQUEST_IDENTITIES` with
zero keys, it unlocks the default Secret Service collection (for example
KeePassXC or gnome-keyring), waits for the prompt to finish, and then
retries the request. Every other message is passed through byte for byte.

## Install

```sh
makepkg -si
systemctl --user edit ssh-agent-guard   # set SSH_AGENT_GUARD_UPSTREAM if not %t/ssh-agent.socket
systemctl --user enable --now ssh-agent-guard.socket
```

Then point clients at the proxy, e.g. in `~/.config/environment.d/ssh.conf`:

```
SSH_AUTH_SOCK=${XDG_RUNTIME_DIR}/ssh-agent-guard.socket
```

## Behaviour

- Each client gets its own upstream connection; requests are relayed as raw
  frames, so constraints, extensions and unknown key types pass through intact.
- The default collection (`ReadAlias("default")`) is looked up on first use
  and cached. A failed lookup is not cached.
- Unlocks are coalesced. Concurrent clients that see zero keys share a
  single unlock flow and prompt.
- If the collection is already unlocked, the request is retried once and the
  empty answer is returned. Nobody is prompted.
- After a real unlock, the request is retried for up to `-key-wait` (default 3s),
  because some secret stores load keys into the agent asynchronously.
- After a dismissed or failed prompt, no new prompt is shown for `-cooldown`
  (default 10s), which avoids a storm of dialogs from parallel `git`/`ssh` runs.
- D-Bus access is through `busctl`. Prompt completion is detected via
  `busctl monitor` (`Prompt.Completed`), with polling of `Locked` as a fallback.

Run `ssh-agent-guard -h` to see all flags. `-listen PATH` runs it without socket activation.
