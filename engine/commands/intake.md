# Intake — program URL to engagement

Start a new engagement from a program URL, platform slug, or local scope file.

## Usage

```
/intake https://hackerone.com/acme
/intake https://bugcrowd.com/acme-corp
/intake https://yeswehack.com/programs/acme
/intake --platform hackerone --slug acme
/intake --scope-file ~/acme-scope.json acme
```

## What it does

1. **Parse** — extract platform + slug from URL
2. **Fetch** — get scope via bb-platforms MCP (or local file)
3. **Convert** — normalize H1/Bugcrowd/YWH scope → engine scope.json
4. **Create** — set up engagement directory with scope, seeds, path restrictions
5. **Report** — show in-scope hosts, seeds, and next steps

## After intake

```
/profile <target>     # understand the app before hunting
/recon <target>       # discover attack surface
/hunt <target>        # start hunting
```

## Implementation

```bash
python3 engine/engine/intake.py start "$1"
```
