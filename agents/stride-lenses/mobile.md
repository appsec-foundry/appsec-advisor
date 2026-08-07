# Mobile client lens

Apply this lens only when the validated manifest carries `mobile` in
`lens_ids`. A mobile runtime is an untrusted client boundary.

- Check `AndroidManifest.xml`, `Info.plist`, and network-security configuration
  for production debug flags, cleartext traffic, or broad transport exceptions.
- Check exported Android components, custom URL schemes, app links, universal
  links, and intent handlers for missing caller or origin validation.
- Check WebView JavaScript bridges, file access, and navigation policy before
  treating web content as able to invoke native capabilities.
- Check session and refresh tokens stored in `SharedPreferences`,
  `UserDefaults`, logs, backups, or other app-readable storage.
- Check custom trust managers and URL-session delegates for disabled TLS
  certificate or hostname verification.

Emit a finding only with an evidenced production-reachable configuration or
code path. Exclude debug-only build variants when the build configuration proves
they cannot ship. Use the normal STRIDE output shape, severity caps, and
remediation requirements.
