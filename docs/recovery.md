# Backup, recovery and uninstall

Settings → **Backup & Recovery** keeps complete backups on this NAS, outside the
package data folder. They include a consistent SQLite snapshot, its encryption
key, saved credentials, ACME accounts, certificate keys and the native change
journal. Backups are root-only (directory 0700, archives 0600); their contents are
never returned through management endpoints. Include this separate directory in
your normal NAS backup. A single NAS disk loss still needs an external backup.

A full backup is created daily, before managed deletions and before uninstall.
**Create full backup** queues one immediately; Activity reports the result. Expand
a backup to choose **Restore these settings**, review its date/ID and profile/host counts, then confirm
`RESTORE SETTINGS`. The immutable recovery helper stops management, saves the
current state, validates archive checksums, paths, SQLite integrity and secret
decryption, then atomically swaps the private state directory and restarts the
app. Interrupted operations in a restored backup require explicit retry. Native
DSM objects are read again by ID; a settings restore never recreates objects that
were deleted in DSM.

If the app cannot open, reinstall the SPK, activate its broker, then use SSH or
DSM Task Scheduler as administrator:

```sh
sudo /usr/local/libexec/synoharbor/synoharbor recover <backup-id>
# Use latest only after checking which backup you intend to restore.
```

The same command works when current private storage is unreadable. Its old
directory is preserved for investigation instead of being destroyed. Archive
verification refuses links, traversal, special files, duplicate members,
unsupported members, checksum failures, invalid databases and undecryptable
secrets. It limits archive size to 512 MiB and individual files to 64 MiB.

## Undoing native DSM changes

**Preview DSM restore** reads fresh native state and lists exact objects and
assignments that rollback would change. Type `RESTORE` to prepare uninstall.
This restores before-images of adopted proxies, removes created proxies, restores
recorded SSL/default/HTTP2 assignments, and removes created certificates only
when no other service uses them. It touches only the recorded SynoHarbor scope.
A full recovery backup is mandatory before rollback starts.

External edits, missing ownership records in older backups and unexpected dependencies block rollback. Native aliases sharing an internal listener retain its last valid access rules when their original native owner disappears; deleting that dependency is blocked until the alias is moved or removed. Explicitly deleted
objects are not resurrected. A failed DSM read is never treated as deletion.
Original certificates needed for restoration must still be valid. Native APIs
may assign a new ID when an original certificate has to be re-imported; the
journal records that mapping. Completed stages are durable so a failed restore
can be retried. Failure never writes an uninstall/erase authorization receipt.

The native reverse proxy target used by Advanced settings is a loopback listener
on the NAS's existing nginx. It does not make a request to the Go manager for each
page view. The last valid native/Advanced routes remain available when management
stops. Automatic renewal and configuration changes require the worker.

## Package Center choices

- **Keep services and settings** is the default. Certificates, native proxies and
  last valid Advanced rules remain. Reinstall the package to resume management.
- **Use prepared DSM restore; keep private settings** requires a successful
  preview/restore while the app is still installed.
- **Use prepared DSM restore; erase private settings** additionally removes the
  package's credentials, keys and settings. Root-private recovery backups remain.

DSM's preuninstall hook validates the completed restore and remaining native
listener dependencies. Cleanup is rejected if restoration is incomplete. Upgrade
hooks never honor uninstall erase choices. Uninstall with restore must be
prepared in the app first, so the user can review native changes while all
components remain available. This follows DSM's lifecycle ordering and avoids
attempting a native rollback from a partially removed package.

The restricted root broker remains available during Package Center's uninstall
checks. Its root-owned service refuses startup without an installed package and
exits when the package INFO file disappears. The API and worker remain package
user processes; no mutable package executable is launched as root for recovery.

Relevant platform references: [DSM lifecycle scripts](https://help.synology.com/developer-guide/synology_package/scripts.html)
and [uninstall wizard fields](https://help.synology.com/developer-guide/synology_package/wizard/WIZARD_UIFILES_v2.html).
