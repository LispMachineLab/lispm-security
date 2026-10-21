EMACS ?= emacs
# lisp/ of lispm-agent and of LispM Desktop (which needs LispM Browser's),
# checkouts beside this one by default.  Security needs neither; with them
# on the load path, the tests of how it works with them run too.
LISPM_AGENT ?= ../lispm-agent/lisp
LISPM_DESKTOP ?= ../lispm-desktop/lisp
LISPM_BROWSER ?= ../lispm-browser/lisp
LOAD_PATH = -L . $(foreach dir,$(wildcard $(LISPM_AGENT) $(LISPM_DESKTOP) $(LISPM_BROWSER)),-L $(dir))

FILES = lispm-security.el lispm-security-toml.el lispm-security-inventory.el \
	lispm-security-rules.el lispm-security-elisp.el lispm-security-pins.el \
	lispm-security-osv.el lispm-security-guard.el lispm-security-ui.el

.PHONY: test compile

# The tests stand in for primitives such as make-process; without native
# trampolines for them, doing so starts no compiler.
test:
	$(EMACS) -Q --batch $(LOAD_PATH) --eval '(setq native-comp-enable-subr-trampolines nil)' \
	  -l test/lispm-security-test.el -f ert-run-tests-batch-and-exit

# A check: the .elc files are removed again, as they would shadow the
# sources of a checkout Emacs loads from.
compile:
	$(EMACS) -Q --batch -L . --eval '(setq byte-compile-error-on-warn t)' \
	  -f batch-byte-compile $(FILES); \
	status=$$?; rm -f *.elc; exit $$status
