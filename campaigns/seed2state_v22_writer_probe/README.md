# seed2state_v22_writer_probe — V5-style GO/BODY FLAT

This package restores the runtime convention used by the working V5-style
campaigns, without chained or nested breakpoint commands.

Operational structure:

- `seed2state_v22_writer_probe_go.txt` installs breakpoints and starts `g`.
  breakpoint commands do not chain through them.
- paths inside breakpoint commands use `C:/Temp/...` to avoid WinDbg backslash
  escaping issues.

Copy the internal directory:

```text
seed2state_v22_writer_probe
```

to:

```text
```

Launch in WinDbg/KD:

```text
bc *
bl
.logclose
```

Expected first automatic marker:

```text
[V22_WRITER_NEWGENEX_ENTRY_F7459951]
```

Key marker:

```text
[V22_WRITER_OUTBUF_FIRST_WRITE]
```


## WinDbg path quoting note

Breakpoint command strings intentionally use doubled backslashes, for example:

```text
```

This is not a filesystem path change. Inside a quoted WinDbg breakpoint command, `\` must be written as `\\` so the stored command resolves to the Windows path `C:\Temp\...` when the breakpoint fires. Direct `$$>a<...` calls outside a breakpoint command may still use ordinary Windows paths.
