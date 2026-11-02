.PHONY: validate status ready preflight zoo

# Secondary convenience targets for macOS/Linux. Windows is canonical; use scripts/*.ps1 there.
validate:
	node scripts/validate-bootstrap.mjs

status:
	node scripts/taskctl.mjs status

ready:
	node scripts/taskctl.mjs ready

preflight:
	./scripts/preflight.sh

# The project zoo: run SURE against the pinned corpus and compare with the baseline.
zoo:
	node scripts/zoo.mjs
