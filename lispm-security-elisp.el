;;; lispm-security-elisp.el --- Reading the code of LispM's skills  -*- lexical-binding: t; -*-

;; Copyright (C) 2026  Ryan.K

;; This file is not part of GNU Emacs.

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU Affero General Public License as published
;; by the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU Affero General Public License for more details.

;; You should have received a copy of the GNU Affero General Public License
;; along with this program.  If not, see <https://www.gnu.org/licenses/>.

;;; Commentary:

;; A LispM skill's code is Lisp, evaluated in the user's Emacs when an
;; agent loads the skill: it can do whatever Emacs can.  Lisp's code is
;; data, so it can be read whole without running any of it: `read'
;; makes no call, and `read-positioning-symbols' tells where each symbol
;; was written.  The blocks read are exactly those LispM evaluates: the
;; source blocks of emacs-lisp marked :lispm load, unescaped as org
;; does; and the Lisp files beside a skill that is a directory, which
;; its code may load.
;;
;; What the code does is told by what it calls and what it changes:
;;
;; - it runs programs, reaches the network, writes files, reads stored
;;   passwords, decodes hidden text, loads or evaluates code it makes,
;;   runs again later on its own, or calls a function whose name it
;;   computes, so that reading cannot tell which;
;; - it changes what decides what agents may do: LispM's policy, the
;;   skills trusted, the servers started, Security's own pins; or
;;   Emacs's own guards, such as which local variables are safe.  Binding
;;   one of them with `let' around a call counts: it changes them while
;;   the call runs;
;; - it changes what other functions do, with advice or by defining them
;;   again: a skill that answers `y-or-n-p' itself answers for the user;
;; - its tools are of a permission class that does not say what they
;;   do: a tool of class read runs without asking, so one that runs
;;   programs must be of class shell.  What a tool does counts what the
;;   skill's own functions it calls do;
;; - it replaces one of LispM's tools by one of its own.
;;
;; Reading cannot follow code that is made at run time, which is why
;; making it is itself a finding.

;;; Code:

(require 'seq)
(require 'subr-x)
(require 'lispm-security)
(require 'lispm-security-rules)

(declare-function lispm-get-tool "lispm-tools" (name))
(declare-function lispm-tool-file "lispm-tools" (tool))

(defconst lispm-security-elisp-calls
  '((process medium shell "Runs programs"
             (shell-command shell-command-to-string async-shell-command call-process
              call-process-region call-process-shell-command process-file
              process-file-shell-command process-lines process-lines-ignore-status start-process
              start-process-shell-command start-file-process start-file-process-shell-command
              make-process compile)
             "It starts programs with everything the user can do: whatever its tools are asked, \
the programs reach the files, the network and the other programs of the computer.")
    (network medium web "Reaches the network"
             (url-retrieve url-retrieve-synchronously url-copy-file url-insert-file-contents url-http
              open-network-stream make-network-process plz request eww-retrieve)
             "It sends and fetches over the network, which is also how data leaves.  Check which \
addresses, and what it sends.")
    (evaluation high exec "Evaluates code it makes or reads"
                (eval eval-region eval-buffer eval-expression eval-last-sexp)
                "Code evaluated at run time cannot be read here first: what it does is whatever the \
text it evaluates says, which may come from a page, a file or the model.")
    (loading medium exec "Loads code from files"
             (load load-file load-library byte-compile native-compile)
             "What a loaded file does is what its code does.  A file beside the skill was read too; \
check that it loads only those.")
    (credentials high read "Reads stored passwords and keys"
                 (auth-source-search auth-source-user-or-password auth-source-pick-first-password
                  auth-info-password secrets-get-secret epa-decrypt-file epg-decrypt-file
                  password-store-get)
                 "It takes passwords and tokens from where the user keeps them.  A skill that does \
must have a reason, and send them nowhere else.")
    (decoding high read "Decodes hidden text"
              (base64-decode-string base64-decode-region base64url-decode-string rot13-string rot13
               decode-hex-string hex-to-string)
              "Encoded text hides from whoever reads the code what it becomes: code to evaluate, \
an address, a command.  Decode it to see.")
    (timers low nil "Runs again later on its own"
            (run-at-time run-with-timer run-with-idle-timer)
            "A timer runs code after the agent's call returned, unasked: a time limit's, as a rule, \
but also one that keeps running.  Check that it stops.")
    (writing low write "Changes files"
             (write-region write-file delete-file delete-directory rename-file copy-file
              copy-directory make-symbolic-link set-file-modes append-to-file)
             "It writes or deletes files.  Check which."))
  "Calls that tell what code does: (RULE SEVERITY CLASS TITLE FUNCTIONS DETAIL).
CLASS is the permission class a LispM tool doing so is of, nil for none.")

(defconst lispm-security-elisp-program-argument
  '((call-process . 0) (call-process-region . 2) (process-file . 0) (process-lines . 0)
    (process-lines-ignore-status . 0) (start-process . 2) (start-file-process . 2)
    (shell-command . 0) (shell-command-to-string . 0) (async-shell-command . 0)
    (call-process-shell-command . 0) (process-file-shell-command . 0)
    (start-process-shell-command . 2) (start-file-process-shell-command . 2) (compile . 0))
  "Which argument of a call starting a program names it, or is its command line.")

(defconst lispm-security-elisp-dynamic-calls
  '(funcall apply funcall-interactively call-interactively apply-partially)
  "Calls of a function given as a value.")

(defconst lispm-security-elisp-name-makers
  '(intern intern-soft make-symbol read read-from-string)
  "Calls that make a symbol, or code, from text.")

(defconst lispm-security-elisp-binders '(let let* dlet letrec cl-letf cl-letf* with-suppressed-warnings)
  "Forms that bind variables while their body runs.")

(defconst lispm-security-elisp-definers
  '(defun defalias fset defmacro defsubst cl-defun cl-defmacro cl-defmethod cl-defgeneric
    define-inline)
  "Forms that define a function they name.")

(defconst lispm-security-elisp-advisers
  '(advice-add advice-remove add-function remove-function define-advice ad-activate)
  "Forms that change what a function does.")

(defconst lispm-security-guarding-variables
  "\\`\\(?:lispm-\\(?:default-policy\\|trusted-skills\\|skill-directories\\|skill-sources\\|write-skill-directory\\|mcp-servers\\|rationale-permissions\\|.*\\(?:polic\\|trust\\|allow\\|permission\\|approv\\)\\)\\|lispm-security-.*\\)\\'"
  "Variables that decide what LispM's agents may do, and Security's own.")

(defconst lispm-security-emacs-guards
  '(enable-local-variables enable-local-eval safe-local-variable-values safe-local-eval-forms
    enable-dir-local-variables auth-sources network-security-level gnutls-verify-error
    tls-checktrust url-proxy-services exec-path process-environment initial-environment
    load-path user-init-file custom-file package-archives package-check-signature
    package-unsigned-archives trusted-content)
  "Variables of Emacs that guard against code and data from elsewhere.")

(defconst lispm-security-guarding-functions
  "\\`\\(?:lispm-.*\\(?:polic\\|trust\\|allow\\|permission\\|approv\\|ask\\|deny\\|action\\)\\|lispm-security-.*\\|y-or-n-p\\|yes-or-no-p\\|read-passwd\\|read-answer\\|read-multiple-choice\\|map-y-or-n-p\\|lispm-call-ask\\|lispm-tool-action\\)\\'"
  "Functions that decide or ask what agents may do.")

(defconst lispm-security-watched-hooks
  '(post-command-hook pre-command-hook after-init-hook emacs-startup-hook kill-emacs-hook
    find-file-hook after-save-hook before-save-hook after-change-functions
    window-configuration-change-hook)
  "Hooks code runs from on everything the user does, or at each start.")

(defconst lispm-security-class-rank
  '((read . 0) (memory . 0) (comm . 0) (lisp . 0) (web . 1) (write . 2) (mcp . 2) (shell . 3) (exec . 4))
  "Permission classes of LispM's tools, by what they let a tool do.")

(defconst lispm-security-unasked-classes '(read memory comm lisp)
  "The classes whose tools LispM runs without asking by default.")

;;;; Reading the code

(defun lispm-security-elisp-read (code)
  "The forms of CODE, read with the positions of their symbols, and an error.
\(FORMS . ERROR): ERROR, a string, says where the code stopped reading,
or is nil."
  (with-temp-buffer
    (with-syntax-table emacs-lisp-mode-syntax-table
      (insert code)
      (goto-char (point-min))
      (let ((read-symbol-shorthands nil) forms problem)
        (condition-case err
            (while (progn (forward-comment (buffer-size)) (not (eobp)))
              (push (read-positioning-symbols (current-buffer)) forms))
          (error (setq problem (format "line %d: %s" (line-number-at-pos)
                                       (error-message-string err)))))
        (cons (nreverse forms) problem)))))

(defun lispm-security--bare (object)
  "OBJECT as a bare symbol, if it is a symbol, with a position or not; else nil."
  (cond ((symbol-with-pos-p object) (bare-symbol object))
        ((symbolp object) object)))

(defun lispm-security--position (form)
  "The position of the first symbol of FORM written, or nil."
  (cond ((symbol-with-pos-p form) (symbol-with-pos-pos form))
        ((consp form)
         (let (position)
           (while (and (consp form) (not position))
             (setq position (lispm-security--position (car form))
                   form (cdr form)))
           position))))

(defun lispm-security--named (form)
  "The symbol FORM names as data: SYM of \\='SYM or #\\='SYM, or nil."
  (and (consp form)
       (memq (lispm-security--bare (car form)) '(quote function))
       (lispm-security--bare (cadr form))))

(defun lispm-security--contains-call (form functions)
  "Non-nil if FORM calls one of FUNCTIONS somewhere, outside quoted data."
  (and (consp form)
       (not (eq (lispm-security--bare (car form)) 'quote))
       (or (memq (lispm-security--bare (car form)) functions)
           (seq-some (lambda (sub) (lispm-security--contains-call sub functions))
                     (ignore-errors (append form nil))))))

(defconst lispm-security--naming-forms
  '(require featurep provide declare-function autoload fboundp boundp eval-after-load
    with-eval-after-load put get function-get function-put symbol-plist make-obsolete
    define-obsolete-function-alias custom-autoload)
  "Forms whose quoted symbols name features or properties, not functions called.")

(defun lispm-security--evaluated (head arguments)
  "Those of ARGUMENTS of a call of HEAD that are code: not names, argument
lists, variables bound or handlers' conditions."
  (pcase head
    ((or 'lambda 'closure) (cdr arguments))
    ((or 'defun 'defmacro 'defsubst 'cl-defun 'cl-defmacro 'define-inline 'cl-defgeneric)
     (cddr arguments))
    ;; (lispm-deftool NAME PARAMS DOCSTRING . BODY)
    ('lispm-deftool (nthcdr 3 arguments))
    ('cl-defmethod (cdr (seq-drop-while (lambda (argument) (not (listp argument))) (cdr arguments))))
    ((or 'let 'let* 'dlet 'letrec 'cl-letf 'cl-letf* 'if-let 'if-let* 'when-let 'when-let*
         'and-let* 'while-let)
     (if (listp (car arguments))
         (append (mapcar (lambda (binding) (and (consp binding) (car (last binding))))
                         (car arguments))
                 (cdr arguments))
       arguments))
    ((or 'dolist 'dotimes 'cl-dolist 'cl-dotimes 'pcase-dolist)
     (cons (and (consp (car arguments)) (cadr (car arguments))) (cdr arguments)))
    ('condition-case
     (cons (cadr arguments)
           (mapcan (lambda (handler) (and (consp handler) (copy-sequence (cdr handler))))
                   (cddr arguments))))
    ((pred (lambda (head) (memq head lispm-security--naming-forms))) nil)
    (_ arguments)))

(defun lispm-security--walk (form visit)
  "Call VISIT with each call in FORM, outermost first; quoted data is skipped.
VISIT gets the symbol, without its position, of what is called, the
arguments, and the call, as read."
  (when (and (consp form) (proper-list-p form))
    (let ((head (lispm-security--bare (car form))))
      (cond ((eq head 'quote))
            ((null head) (dolist (sub form) (lispm-security--walk sub visit)))
            (t (funcall visit head (cdr form) form)
               (dolist (sub (lispm-security--evaluated head (cdr form)))
                 (lispm-security--walk sub visit)))))))

(defun lispm-security--function-names (head arguments)
  "The functions the call of HEAD names as data among ARGUMENTS: #\='F, \='F."
  (unless (memq head lispm-security--naming-forms)
    (seq-keep #'lispm-security--named arguments)))

;;;; What code does

(defun lispm-security--call-rule (function)
  "The rule of `lispm-security-elisp-calls' FUNCTION falls under, or nil."
  (seq-find (lambda (rule) (memq function (nth 4 rule))) lispm-security-elisp-calls))

(defun lispm-security--uses (form)
  "The functions of `lispm-security-elisp-calls' FORM calls or names."
  (let (uses)
    (lispm-security--walk
     form
     (lambda (head arguments _)
       (dolist (function (cons head (lispm-security--function-names head arguments)))
         (when (lispm-security--call-rule function) (push function uses)))))
    (delete-dups uses)))

(defun lispm-security--calls (form)
  "The functions FORM calls by name, directly or named as data."
  (let (calls)
    (lispm-security--walk
     form
     (lambda (head arguments _)
       (setq calls (append (cons head (lispm-security--function-names head arguments)) calls))))
    (delete-dups calls)))

(defun lispm-security--definitions (forms)
  "The functions FORMS define at top level: an alist (NAME . BODY)."
  (let (definitions)
    (dolist (form forms)
      (lispm-security--walk
       form
       (lambda (head arguments _)
         (pcase head
           ((or 'defun 'defsubst 'cl-defun 'defmacro 'cl-defmacro)
            (when-let* ((name (lispm-security--bare (car arguments))))
              (push (cons name (cddr arguments)) definitions)))
           ('defalias
            (when-let* ((name (lispm-security--named (car arguments))))
              (push (cons name (cdr arguments)) definitions)))))))
    definitions))

(defun lispm-security--class-of (uses)
  "The permission class code making USES, functions, needs; nil for none."
  (let ((class nil))
    (dolist (use uses)
      (let ((needed (nth 2 (lispm-security--call-rule use))))
        (when (and needed (> (alist-get needed lispm-security-class-rank 0)
                             (alist-get class lispm-security-class-rank -1)))
          (setq class needed))))
    class))

(defun lispm-security--argument (arguments keyword)
  "The value after KEYWORD in ARGUMENTS, keyword arguments as read."
  (let (value)
    (while (and arguments (not value))
      (when (eq (lispm-security--bare (car arguments)) keyword)
        (setq value (cadr arguments)))
      (setq arguments (cdr arguments)))
    value))

(defun lispm-security--fixed-program-p (head arguments)
  "Non-nil if the call of HEAD with ARGUMENTS starts a program it names as
written, or runs a command line written out whole."
  (if (eq head 'make-process)
      (let ((command (lispm-security--argument arguments :command)))
        (and (consp command)
             (pcase (lispm-security--bare (car command))
               ((or 'list 'cons 'list*) (stringp (cadr command)))
               ((or 'quote '\`) (and (consp (cadr command)) (stringp (car (cadr command))))))))
    (when-let* ((index (alist-get head lispm-security-elisp-program-argument)))
      (stringp (nth index arguments)))))

(defun lispm-security--computed-programs (form)
  "The functions FORM starts programs with that it does not name as written."
  (let (computed)
    (lispm-security--walk
     form
     (lambda (head arguments _)
       (when (and (or (eq head 'make-process) (assq head lispm-security-elisp-program-argument))
                  (not (lispm-security--fixed-program-p head arguments)))
         (push head computed))
       ;; Given as a value: (apply #'call-process "git" ...) names its
       ;; program next; given anywhere else, it is called with arguments
       ;; no one wrote here.
       (dolist (named (lispm-security--function-names head arguments))
         (when (or (eq named 'make-process) (assq named lispm-security-elisp-program-argument))
           (unless (and (memq head '(apply funcall))
                        (eq (lispm-security--named (car arguments)) named)
                        (lispm-security--fixed-program-p named (cdr arguments)))
             (push named computed))))))
    (delete-dups computed)))

(defun lispm-security--transitive (collect body definitions)
  "What COLLECT finds in BODY and in the functions of DEFINITIONS it calls.
COLLECT is called with each form and returns a list."
  (let ((seen nil) (found nil) (pending (list body)))
    (while pending
      (let ((form (pop pending)))
        (setq found (append (funcall collect form) found))
        (dolist (called (lispm-security--calls form))
          (when-let* (((not (memq called seen)))
                      (definition (assq called definitions)))
            (push called seen)
            (push (cdr definition) pending)))))
    (delete-dups found)))

;;;; Findings

(defun lispm-security--elisp-findings (item forms file line-of)
  "Findings of the code FORMS of ITEM, written in FILE.
LINE-OF turns a position in the code read into a line of FILE."
  (let* ((definitions (lispm-security--definitions forms))
         (defined (mapcar #'car definitions))
         (counts (make-hash-table :test #'equal))
         findings)
    (cl-flet ((add (rule severity title form &rest properties)
                ;; Three findings a rule and symbol at most, for code that repeats itself.
                (let ((key (list rule (plist-get properties :about))))
                  (when (< (gethash key counts 0) 3)
                    (puthash key (1+ (gethash key counts 0)) counts)
                    (push (apply #'lispm-security-finding rule severity item title
                                 :file file
                                 :line (when-let* ((position (lispm-security--position form)))
                                         (funcall line-of position))
                                 (lispm-security--without properties :about))
                          findings)))))
      (dolist (form forms)
        (lispm-security--walk
         form
         (lambda (head arguments call)
           (progn
             ;; What it calls.
             (dolist (function (cons head (lispm-security--function-names head arguments)))
               (when-let* ((rule (lispm-security--call-rule function)))
                 (pcase-let ((`(,id ,severity ,_ ,title ,_ ,detail) rule))
                   ;; A program named as written is a lesser finding.
                   (when (and (eq id 'process)
                              (if (eq function head)
                                  (lispm-security--fixed-program-p head arguments)
                                (and (memq head '(apply funcall))
                                     (lispm-security--fixed-program-p function (cdr arguments)))))
                     (setq severity 'low))
                   (add id severity (format "%s: %s" title function) call
                        :about function :evidence (symbol-name function) :detail detail))))
             ;; Functions whose names it computes.
             (when (and (memq head lispm-security-elisp-dynamic-calls)
                        (lispm-security--contains-call (car arguments) lispm-security-elisp-name-makers))
               (add 'computed-call 'high (format "Calls a function whose name it computes, with %s" head)
                    call :about head
                    :evidence (lispm-security-evidence (format "%S" (lispm-security--plain call)))
                    :detail "Which function runs is decided when the code runs, from text: reading \
cannot tell, and it is how code hides what it calls."))
             ;; Variables it changes, or binds around its calls.  Binding
             ;; Emacs's own around a call is how a program is given its
             ;; environment, and lasts the call only.
             (pcase-dolist (`(,variable . ,bound) (lispm-security--changed head arguments))
               (cond ((string-match-p lispm-security-guarding-variables (symbol-name variable))
                      (add 'changes-policy 'critical
                           (format "%s %s, which decides what agents may do"
                                   (if bound "Binds" "Changes") variable)
                           call :about variable :evidence (symbol-name variable)
                           :detail "A skill that changes it gives itself, or any agent, what the \
user did not: calls that run without asking, code trusted unseen, servers started.  Bound around a \
call, it does so while the call runs.  No skill needs to; the user changes it."))
                     ((and (not bound) (memq variable lispm-security-emacs-guards))
                      (add 'changes-guard 'high
                           (format "Changes %s, one of Emacs's guards" variable)
                           call :about variable :evidence (symbol-name variable)
                           :detail "It decides what Emacs trusts: local variables evaluated, \
certificates checked, where programs and libraries are found.  Changed, other code can run as the \
user's own."))))
             ;; Functions it changes.
             (when-let* ((target (lispm-security--changed-function head arguments)))
               (let ((guarding (string-match-p lispm-security-guarding-functions (symbol-name target))))
                 (cond ((memq head lispm-security-elisp-advisers)
                        (add 'advises (if guarding 'critical 'high)
                             (format "Changes what %s does" target)
                             call :about target :evidence (symbol-name target)
                             :detail (if guarding
                                         "That function decides or asks what agents may do: \
changed, the skill answers in the user's place."
                                       "Advice changes the function for all of Emacs, every \
caller included, for as long as Emacs runs.")))
                       ((and (not (memq target defined)) (eq head 'fset))
                        (add 'redefines (if guarding 'critical 'high)
                             (format "Replaces the function %s" target)
                             call :about target :evidence (symbol-name target)
                             :detail "Every caller then runs the skill's code instead."))
                       ((and (fboundp target) (symbol-file target 'defun)
                             (not (lispm-security--same-file-p (symbol-file target 'defun) file)))
                        (add 'redefines (if guarding 'critical 'high)
                             (format "Defines %s again, a function of %s" target
                                     (file-name-nondirectory (symbol-file target 'defun)))
                             call :about target :evidence (symbol-name target)
                             :detail "Every caller then runs the skill's code instead of the \
library's.")))))
             ;; Hooks it adds to.  One that decides what agents may do,
             ;; such as where skills come from, is a variable changed.
             (when-let* (((eq head 'add-hook))
                         (hook (lispm-security--named (car arguments)))
                         ((not (string-match-p lispm-security-guarding-variables (symbol-name hook))))
                         ((or (memq hook lispm-security-watched-hooks)
                              (string-match-p "\\`lispm-" (symbol-name hook)))))
               (add 'hooks 'medium (format "Runs from %s" hook) call :about hook
                    :evidence (symbol-name hook)
                    :detail "Its function then runs on its own, each time the hook runs, \
beyond any call of the skill's tools."))
             ;; Its tools.
             (when (eq head 'lispm-deftool)
               (setq findings (append (lispm-security--tool-findings item call definitions file line-of)
                                      findings))))))))
    (nreverse findings)))

(defun lispm-security--without (plist key)
  "PLIST without KEY and its value."
  (let (result)
    (while plist
      (unless (eq (car plist) key)
        (setq result (cons (cadr plist) (cons (car plist) result))))
      (setq plist (cddr plist)))
    (nreverse result)))

(defun lispm-security--plain (form)
  "FORM with its symbols' positions dropped."
  (cond ((symbol-with-pos-p form) (bare-symbol form))
        ((consp form) (cons (lispm-security--plain (car form)) (lispm-security--plain (cdr form))))
        ((vectorp form) (vconcat (mapcar #'lispm-security--plain form)))
        (t form)))

(defun lispm-security--same-file-p (a b)
  "Non-nil if A and B name one file, ignoring an .el or .elc extension."
  (and a b (equal (file-name-sans-extension (expand-file-name a))
                  (file-name-sans-extension (expand-file-name b)))))

(defun lispm-security--changed (head arguments)
  "The variables the call of HEAD with ARGUMENTS changes or binds:
\((VARIABLE . BOUND) ...), BOUND non-nil for one bound around a body."
  (let ((bound (memq head lispm-security-elisp-binders))
        (symbols
         (pcase head
           ((or 'setq 'setq-default 'setq-local 'setopt)
            (seq-map-indexed (lambda (argument index) (and (cl-evenp index) argument)) arguments))
           ((or 'set 'set-default 'customize-set-variable 'customize-save-variable 'customize-set-value
                'add-to-list 'add-to-ordered-list 'add-hook 'remove-hook 'makunbound)
            (list (lispm-security--named (car arguments))))
           ((or 'push 'cl-pushnew) (list (cadr arguments)))
           ((or 'pop 'cl-incf 'cl-decf) (list (car arguments)))
           ((or 'setf 'cl-callf)
            (seq-map-indexed (lambda (argument index)
                               (and (cl-evenp index)
                                    (if (consp argument)
                                        ;; (setf (lispm-agent-policy agent) ...)
                                        (let ((accessor (lispm-security--bare (car argument))))
                                          (and accessor
                                               (string-match-p "\\`lispm-agent-\\(?:policy\\|allowed\\)\\'"
                                                               (symbol-name accessor))
                                               (intern "lispm-default-policy")))
                                      argument)))
                             (if (eq head 'cl-callf) (cdr arguments) arguments)))
           ((or 'defconst 'defcustom) (list (car arguments)))
           ('custom-set-variables
            (mapcar (lambda (entry)
                      ;; '(VARIABLE VALUE ...)
                      (and (consp entry) (eq (lispm-security--bare (car entry)) 'quote)
                           (consp (cadr entry)) (car (cadr entry))))
                    arguments))
           ((pred (lambda (head) (memq head lispm-security-elisp-binders)))
            (mapcar (lambda (binding) (if (consp binding) (car binding) binding))
                    (and (listp (car arguments)) (car arguments)))))))
    (mapcar (lambda (variable) (cons variable (and bound t)))
            (delete-dups (delq nil (mapcar #'lispm-security--bare symbols))))))

(defun lispm-security--changed-function (head arguments)
  "The function the call of HEAD with ARGUMENTS defines or advises, or nil."
  (cond ((memq head '(advice-add advice-remove fset defalias))
         (lispm-security--named (car arguments)))
        ((memq head '(add-function remove-function))
         ;; (add-function :around (symbol-function 'f) ...)
         (let ((place (cadr arguments)))
           (and (consp place) (lispm-security--named (cadr place)))))
        ((eq head 'define-advice) (lispm-security--bare (car arguments)))
        ((memq head lispm-security-elisp-definers) (lispm-security--bare (car arguments)))))

(defun lispm-security--tool-findings (item call definitions file line-of)
  "Findings of the tool CALL defines, (lispm-deftool NAME PARAMS DOC . BODY).
DEFINITIONS are the skill's functions, whose uses its tools' count;
ITEM, FILE and LINE-OF as for `lispm-security--elisp-findings'."
  (let* ((name (lispm-security--bare (nth 1 call)))
         (body (nthcdr 4 call))
         (class 'read)
         (where (lambda (form) (when-let* ((position (lispm-security--position form)))
                                 (funcall line-of position))))
         findings)
    (while (keywordp (lispm-security--bare (car body)))
      (when (eq (lispm-security--bare (car body)) :permission)
        (setq class (or (lispm-security--bare (cadr body)) class)))
      (setq body (cddr body)))
    (let* ((uses (lispm-security--transitive #'lispm-security--uses body definitions))
           (needed (lispm-security--class-of uses))
           (unasked (memq class lispm-security-unasked-classes)))
      (when (and needed (> (alist-get needed lispm-security-class-rank 0)
                           (alist-get class lispm-security-class-rank 0)))
        ;; A program named as written does what it does whatever the
        ;; model asks; one whose name or command line is computed does
        ;; whatever the computing makes of the model's arguments.
        (let* ((computed (or (eq needed 'exec)
                             (lispm-security--transitive #'lispm-security--computed-programs
                                                         body definitions)))
               (severity (cond ((and unasked (memq needed '(shell exec))) (if computed 'critical 'medium))
                               (unasked 'high)
                               (t 'low))))
          (push (lispm-security-finding
                 'tool-class severity item
                 (format "Tool %s is of class %s%s, yet %s" name class
                         (if unasked ", which runs without asking" "")
                         (downcase (nth 3 (lispm-security--call-rule
                                           (seq-find (lambda (use)
                                                       (eq (nth 2 (lispm-security--call-rule use)) needed))
                                                     uses)))))
                 :file file :line (funcall where call)
                 :evidence (format "%s, using %s" (if (eq class 'read) "no :permission (read)"
                                                    (format ":permission %s" class))
                                   (mapconcat #'symbol-name uses ", "))
                 :detail (concat
                          (format "LispM asks the user before a call of a tool by its class.  This one's \
class lets it run as a %s tool would, but what it does needs the class %s, so its calls are not asked \
about as they should be." class needed)
                          (cond ((not unasked) "  They are asked about all the same, as of the lesser class.")
                                (computed "  What it runs is computed, from what the model passes it: \
a class that hides that is how a skill gets past the user.")
                                (t "  The programs it runs are named as written, so check what their \
arguments let the model choose."))))
                findings))))
    (when-let* (((fboundp 'lispm-get-tool))
                (existing (lispm-get-tool (symbol-name name)))
                (existing-file (ignore-errors (lispm-tool-file existing)))
                ((not (lispm-security--same-file-p existing-file file))))
      (push (lispm-security-finding
             'replaces-tool 'critical item (format "Replaces LispM's tool %s" name)
             :file file :line (funcall where call) :evidence (symbol-name name)
             :detail (format "The tool %s of %s is replaced by the skill's own once it loads: agents \
calling it then run the skill's code, under the old tool's name." name
                             (file-name-nondirectory existing-file)))
            findings))
    findings))

;;;; Checking

(defun lispm-security-elisp-code-findings (item code file &optional line)
  "Findings of the Lisp CODE of ITEM, written in FILE from LINE."
  (let ((line (or line 1)))
    (pcase-let ((`(,forms . ,problem) (lispm-security-elisp-read code)))
      (let ((symbols-with-pos-enabled t))
        (append
         (and problem
              (list (lispm-security-finding
                     'unreadable-code 'low item "Holds code that does not read"
                     :file file :evidence problem
                     :detail "LispM evaluates none of a block that does not read whole; the rest was \
read here.")))
         (with-temp-buffer
           (insert code)
           (lispm-security--elisp-findings
            item forms file
            (lambda (position) (+ line -1 (line-number-at-pos (min position (point-max)))))))
         ;; Hidden text in its strings and symbols; files of credentials it names.
         (lispm-security-text-findings item code file line "its code"))))))

(defun lispm-security-elisp-check (items)
  "The findings of the code of ITEMS that are LispM's skills."
  (mapcan
   (lambda (item)
     (when (and (eq (plist-get item :kind) 'skill) (eq (plist-get item :format) 'org))
       (let ((file (plist-get item :file)))
         (append
          (mapcan (pcase-lambda (`(,line . ,code))
                    (lispm-security-elisp-code-findings item code file line))
                  (lispm-security-org-blocks (lispm-security-read-text (expand-file-name file))))
          (mapcan (lambda (other)
                    (when (string-suffix-p ".el" other)
                      (lispm-security-elisp-code-findings item (lispm-security-read-text other)
                                                          (abbreviate-file-name other))))
                  (cdr (lispm-security-skill-files item)))))))
   items))

(add-hook 'lispm-security-check-functions #'lispm-security-elisp-check t)

(provide 'lispm-security-elisp)
;;; lispm-security-elisp.el ends here
