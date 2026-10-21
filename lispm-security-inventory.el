;;; lispm-security-inventory.el --- What agents are given to run  -*- lexical-binding: t; -*-

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

;; What each agent of this Emacs is given, found where the agent itself
;; finds it, and read without running anything:
;;
;;   LispM        `lispm-mcp-servers'; the skills of
;;                `lispm-skill-directories' and of the projects' own
;;                .lispm/skills/
;;   Claude Code  ~/.claude.json (the user's servers, and each
;;                project's), the projects' .mcp.json, its plugins'
;;                .mcp.json; the skills of ~/.claude/skills/, of the
;;                plugins and of the projects' .claude/skills/
;;   Codex        ~/.codex/config.toml and its plugins' .mcp.json; the
;;                skills of ~/.codex/skills/ and of its plugins
;;   Emacs        the packages installed
;;
;; Of a server it runs, it tells what that server is: npx's and uvx's
;; package, as named and as it was last installed, with what it brought
;; along, read from npx's cache (~/.npm/_npx/, a directory each set of
;; packages, a lockfile in it) and from uv's environments; a container's
;; image.  A package named without an exact version is not pinned: the
;; next start may run another.

;;; Code:

(require 'seq)
(require 'subr-x)
(require 'lispm-security)
(require 'lispm-security-toml)

(defvar package-alist)
(defvar lispm-mcp-servers)
(defvar lispm-skill-directories)
(defvar lispm-write-skill-directory)
(declare-function package-desc-version "package" (desc))
(declare-function package-desc-dir "package" (desc))
(declare-function package-desc-kind "package" (desc))
(declare-function package-desc-archive "package" (desc))
(declare-function package-version-join "package" (vlist))
(declare-function project-known-project-roots "project" ())

(defcustom lispm-security-claude-directory "~/.claude/"
  "Where Claude Code keeps its settings, skills and plugins."
  :group 'lispm-security
  :type 'directory)

(defcustom lispm-security-claude-config-file "~/.claude.json"
  "Claude Code's file of the user's and projects' MCP servers."
  :group 'lispm-security
  :type 'file)

(defcustom lispm-security-codex-directory "~/.codex/"
  "Where Codex keeps config.toml, its skills and its plugins."
  :group 'lispm-security
  :type 'directory)

(defcustom lispm-security-npm-cache nil
  "npm's cache, where npx installs the packages it runs; nil for npm's own:
$npm_config_cache, or ~/.npm/."
  :group 'lispm-security
  :type '(choice (const :tag "npm's own" nil) directory))

(defcustom lispm-security-uv-cache nil
  "uv's cache, where uvx makes the environments it runs; nil for uv's own:
$UV_CACHE_DIR, or ~/.cache/uv/."
  :group 'lispm-security
  :type '(choice (const :tag "uv's own" nil) directory))

(defcustom lispm-security-uv-tools nil
  "Where `uv tool install' puts tools, which uvx runs instead; nil for
uv's own: $UV_TOOL_DIR, or ~/.local/share/uv/tools/."
  :group 'lispm-security
  :type '(choice (const :tag "uv's own" nil) directory))

;;;; Reading

(defun lispm-security--get (table key)
  "The value of KEY, a string, in TABLE: an alist keyed by strings or symbols."
  (cdr (or (assoc key table) (assq (intern key) table))))

(defun lispm-security--json (file)
  "The JSON in FILE, as alists and vectors, or nil.
A FILE that is there but does not read is noted in
`lispm-security-unreadable'."
  (when (file-readable-p file)
    (condition-case err
        (with-temp-buffer
          (insert-file-contents file)
          (json-parse-buffer :object-type 'alist :array-type 'array
                             :null-object nil :false-object :false))
      (error (push (cons file (error-message-string err)) lispm-security-unreadable)
             nil))))

(defun lispm-security--toml (file)
  "The TOML in FILE, or nil, as `lispm-security--json'."
  (when (file-readable-p file)
    (condition-case err
        (lispm-security-toml-read-file file)
      (error (push (cons file (error-message-string err)) lispm-security-unreadable)
             nil))))

(defun lispm-security--strings (value)
  "VALUE, a vector or list, as a list of strings; nil for anything else."
  (when (or (vectorp value) (listp value))
    (seq-filter #'stringp (append value nil))))

(defun lispm-security--table-strings (value)
  "VALUE, a table of strings by name, as an alist of strings: (NAME . STRING).
VALUE is a JSON object or a TOML table (alists), or a plist of keywords
as mcp.el takes a server's :env."
  (cond ((and (consp value) (keywordp (car value)))
         (mapcar (lambda (pair)
                   (cons (substring (symbol-name (car pair)) 1) (format "%s" (cadr pair))))
                 (seq-partition value 2)))
        ((listp value)
         (delq nil (mapcar (lambda (entry)
                             (and (consp entry)
                                  (cons (format "%s" (car entry)) (format "%s" (cdr entry)))))
                           value)))))

;;;; What a server runs

(defun lispm-security--npm-cache ()
  "npm's cache directory."
  (file-name-as-directory
   (expand-file-name (or lispm-security-npm-cache (getenv "npm_config_cache") "~/.npm/"))))

(defun lispm-security--uv-cache ()
  "uv's cache directory."
  (file-name-as-directory
   (expand-file-name (or lispm-security-uv-cache (getenv "UV_CACHE_DIR") "~/.cache/uv/"))))

(defun lispm-security--uv-tools ()
  "uv's directory of installed tools."
  (file-name-as-directory
   (expand-file-name (or lispm-security-uv-tools (getenv "UV_TOOL_DIR") "~/.local/share/uv/tools/"))))

(defconst lispm-security--exact-version
  "\\`v?[0-9]+\\.[0-9]+\\.[0-9]+\\(?:[-+][0-9A-Za-z.+-]+\\)?\\'"
  "What an exact npm version looks like, as opposed to a range or a tag.")

(defun lispm-security-npm-spec (spec)
  "The package npx SPEC names: (NAME . VERSION-OR-RANGE), or nil.
VERSION-OR-RANGE is nil for SPEC naming none, which is the latest.  A
SPEC that is a path, a URL or a git repository names no package of the
registry: nil."
  (cond ((string-match-p "\\`\\(?:[./~]\\|[a-z+]+:\\|git\\(?:hub\\)?:\\)" spec) nil)
        ((string-match "\\`\\(@[^/@]+/[^@]+\\|[^@]+\\)\\(?:@\\(.*\\)\\)?\\'" spec)
         (cons (match-string 1 spec) (match-string 2 spec)))))

(defun lispm-security--npx-packages (args)
  "The packages npx runs with ARGS, its arguments: a list of specs."
  (let (packages command)
    (while (and args (not command))
      (let ((arg (pop args)))
        (cond ((member arg '("-p" "--package")) (push (pop args) packages))
              ((string-prefix-p "--package=" arg) (push (substring arg 10) packages))
              ((member arg '("-c" "--call")) (setq command t))
              ((string-prefix-p "-" arg))
              (t (setq command arg)))))
    (or (nreverse packages) (and (stringp command) (list command)))))

(defvar lispm-security--npx-index nil
  "npx's cache as the scan going on read it: ((SPECS . DIRECTORY) ...),
SPECS sorted; (nil) once read and found empty.")

(defun lispm-security--npx-index ()
  "The directories of npx's cache, each with the specs it was installed for."
  (or lispm-security--npx-index
      (setq lispm-security--npx-index
            (let ((root (expand-file-name "_npx/" (lispm-security--npm-cache))))
              (or (delq nil
                        (mapcar (lambda (directory)
                                  (when-let* ((json (lispm-security--json
                                                     (expand-file-name "package.json" directory)))
                                              (specs (lispm-security--strings
                                                      (lispm-security--get
                                                       (lispm-security--get json "_npx") "packages"))))
                                    (cons (sort specs #'string<) directory)))
                                (and (file-directory-p root)
                                     (directory-files root t "\\`[0-9a-f]+\\'"))))
                  ;; Read, and found empty: not read again in this scan.
                  (list nil))))))

(defun lispm-security--npm-lock-packages (directory direct)
  "The packages installed in DIRECTORY, by its package-lock.json.
DIRECT are the names of those npx was asked for."
  (when-let* ((lock (lispm-security--json (expand-file-name "package-lock.json" directory)))
              (packages (lispm-security--get lock "packages")))
    (delq nil
          (mapcar (pcase-lambda (`(,path . ,entry))
                    (let* ((path (format "%s" path))
                           (name (and (string-match "node_modules/\\(\\(?:@[^/]+/\\)?[^/]+\\)\\'" path)
                                      (match-string 1 path)))
                           (version (lispm-security--get entry "version")))
                      (when (and name (stringp version) (not (eq (lispm-security--get entry "link") t)))
                        (lispm-security-package
                         "npm" name version
                         :direct (and (member name direct) t)
                         :install-script (eq (lispm-security--get entry "hasInstallScript") t)))))
                  packages))))

(defun lispm-security-npx-runs (args)
  "What npx runs with ARGS: (:launcher npx :specs SPECS :packages PACKAGES).
PACKAGES are those of the specs, at the versions of npx's cache if it
has them, else as named, and what they depend on, from the cache."
  (let* ((specs (lispm-security--npx-packages args))
         (named (delq nil (mapcar #'lispm-security-npm-spec specs)))
         (cached (cdr (assoc (sort (copy-sequence specs) #'string<) (lispm-security--npx-index))))
         (installed (and cached (lispm-security--npm-lock-packages cached (mapcar #'car named)))))
    (list :launcher 'npx :specs specs :cache cached
          :packages
          (append
           (mapcar (pcase-lambda (`(,name . ,version))
                     (let* ((exact (and version (string-match-p lispm-security--exact-version version)))
                            (found (seq-find (lambda (package)
                                               (and (plist-get package :direct)
                                                    (equal (plist-get package :name) name)))
                                             installed)))
                       (lispm-security-package
                        "npm" name (or (plist-get found :version) (and exact (string-remove-prefix "v" version)))
                        :direct t :pinned (and exact t) :named version
                        :install-script (plist-get found :install-script))))
                   named)
           (seq-remove (lambda (package) (plist-get package :direct)) installed)))))

(defun lispm-security-pypi-spec (spec)
  "The package uvx SPEC names: (NAME . VERSION-OR-RANGE), or nil for a path
or URL.  VERSION-OR-RANGE is as written after the name, == and @
included, or nil for none."
  (cond ((string-match-p "\\`\\(?:[./~]\\|[a-z+]+:\\)" spec) nil)
        ((string-match "\\`\\([A-Za-z0-9][A-Za-z0-9._-]*\\)\\(?:\\[[^]]*\\]\\)?[ \t]*\\(.*\\)\\'" spec)
         (let ((rest (string-trim (match-string 2 spec))))
           (cons (match-string 1 spec) (and (not (string-empty-p rest)) rest))))))

(defun lispm-security--pypi-exact (version)
  "The version VERSION, as written after a name, fixes, or nil."
  (and version
       (string-match "\\`\\(?:==\\|@\\)[ \t]*\\([0-9][0-9A-Za-z.+!-]*\\)\\'" version)
       (match-string 1 version)))

(defun lispm-security--uvx-packages (args)
  "The packages uvx runs with ARGS: (MAIN . WITH), specs."
  (let (main with command)
    (while (and args (not command))
      (let ((arg (pop args)))
        (cond ((equal arg "--from") (setq main (pop args)))
              ((string-prefix-p "--from=" arg) (setq main (substring arg 7)))
              ((equal arg "--with") (push (pop args) with))
              ((string-prefix-p "--with=" arg) (push (substring arg 7) with))
              ((member arg '("--python" "-p" "--index-url" "--extra-index-url" "--index"
                             "--default-index" "--with-requirements" "--with-editable"
                             "--directory" "--project" "--config-file" "--cache-dir"))
               (pop args))
              ((string-prefix-p "-" arg))
              (t (setq command arg)))))
    (cons (or main command) (nreverse with))))

(defun lispm-security--dist-infos (site-packages)
  "The packages installed in SITE-PACKAGES: ((NAME . VERSION) ...)."
  (when (file-directory-p site-packages)
    (mapcar (lambda (directory)
              (let ((base (string-remove-suffix ".dist-info" (file-name-nondirectory directory))))
                (cons (substring base 0 (string-search "-" base))
                      (substring base (1+ (string-search "-" base))))))
            (directory-files site-packages t "\\`[^-]+-[^-].*\\.dist-info\\'"))))

(defun lispm-security--uv-environments ()
  "The site-packages of uv's environments and installed tools, the newest first."
  (let ((roots (append (file-expand-wildcards
                        (concat (lispm-security--uv-cache) "environments-v2/*/*/lib/python*/site-packages"))
                       (file-expand-wildcards
                        (concat (lispm-security--uv-tools) "*/lib/python*/site-packages")))))
    (sort roots (lambda (a b) (time-less-p (file-attribute-modification-time (file-attributes b))
                                           (file-attribute-modification-time (file-attributes a)))))))

(defun lispm-security-uvx-runs (args)
  "What uvx runs with ARGS: (:launcher uvx :specs SPECS :packages PACKAGES).
The versions are those of the newest environment of uv's holding the
main package, if one does, with what is installed beside it."
  (pcase-let* ((`(,main . ,with) (lispm-security--uvx-packages args))
               (specs (delq nil (cons main with)))
               (named (delq nil (mapcar #'lispm-security-pypi-spec specs)))
               (main-name (and named (lispm-security-pypi-name (car (car named)))))
               (environment
                (and main-name
                     (seq-find (lambda (site)
                                 (seq-find (lambda (info) (equal (lispm-security-pypi-name (car info)) main-name))
                                           (lispm-security--dist-infos site)))
                               (lispm-security--uv-environments))))
               (installed (and environment (lispm-security--dist-infos environment))))
    (list :launcher 'uvx :specs specs :environment environment
          :packages
          (append
           (mapcar (pcase-lambda (`(,name . ,version))
                     (let ((exact (lispm-security--pypi-exact version))
                           (found (cdr (seq-find (lambda (info)
                                                   (equal (lispm-security-pypi-name (car info))
                                                          (lispm-security-pypi-name name)))
                                                 installed))))
                       (lispm-security-package "PyPI" name (or found exact)
                                               :direct t :pinned (and exact t) :named version)))
                   named)
           (delq nil (mapcar (pcase-lambda (`(,name . ,version))
                               (unless (seq-find (lambda (spec)
                                                   (equal (lispm-security-pypi-name (car spec))
                                                          (lispm-security-pypi-name name)))
                                                 named)
                                 (lispm-security-package "PyPI" name version)))
                             installed))))))

(defun lispm-security-docker-runs (args)
  "What `docker ARGS' runs, for `docker run': (:launcher docker :image IMAGE)."
  (when (equal (car args) "run")
    (let ((args (cdr args)) image)
      (while (and args (not image))
        (let ((arg (pop args)))
          (cond ((member arg '("-e" "--env" "-v" "--volume" "--name" "--network" "-p" "--publish"
                               "--mount" "--env-file" "-w" "--workdir" "-u" "--user" "--entrypoint"
                               "--platform" "-l" "--label" "--add-host" "--cap-add" "--cap-drop"
                               "--device" "--dns" "-h" "--hostname" "--pull" "--memory" "-m"
                               "--cpus" "--security-opt" "--tmpfs" "--ulimit" "--runtime"))
                 (pop args))
                ((string-prefix-p "-" arg))
                (t (setq image arg)))))
      (and image (list :launcher 'docker :image image
                       :pinned (and (string-search "@sha256:" image) t))))))

(defun lispm-security-runs (command args)
  "What a server started as COMMAND with ARGS runs, as far as can be told.
A plist: :launcher (`npx', `uvx', `docker', `shell' or nil) and, by
launcher, :specs and :packages, or :image; nil for COMMAND nil."
  (when (stringp command)
    (let ((program (file-name-nondirectory command))
          (args (lispm-security--strings args)))
      (pcase program
        ((or "npx" "bunx") (lispm-security-npx-runs args))
        ("npm" (and (equal (car args) "exec") (lispm-security-npx-runs (cdr args))))
        ("pnpm" (and (equal (car args) "dlx") (lispm-security-npx-runs (cdr args))))
        ("uvx" (lispm-security-uvx-runs args))
        ("uv" (and (equal (car args) "tool") (equal (cadr args) "run")
                   (lispm-security-uvx-runs (cddr args))))
        ((or "docker" "podman") (lispm-security-docker-runs args))
        ((or "sh" "bash" "zsh" "dash" "fish")
         (and (member "-c" args) (list :launcher 'shell :line (cadr (member "-c" args)))))))))

;;;; Servers and skills

(defun lispm-security-server (agent id name file config &rest properties)
  "The item of AGENT's MCP server NAME, as CONFIG describes it, in FILE.
CONFIG is a JSON object or TOML table (alists) or a LispM server's plist;
ID makes its item's :id unique.  PROPERTIES are added to the item."
  (let* ((get (if (keywordp (car-safe config))
                  (lambda (key) (plist-get config (intern (concat ":" key))))
                (lambda (key) (lispm-security--get config key))))
         (command (funcall get "command"))
         (args (lispm-security--strings (funcall get "args")))
         (normal (list :command command :args args
                       :env (lispm-security--table-strings (funcall get "env"))
                       :url (funcall get "url")
                       :headers (lispm-security--table-strings
                                 (or (funcall get "headers") (funcall get "http_headers")))
                       :token (funcall get "token")
                       :permission (funcall get "permission"))))
    (append (list :id (format "%s/server/%s" agent id) :agent agent :kind 'mcp-server
                  :name name :file (and file (abbreviate-file-name (expand-file-name file)))
                  :config normal
                  :disabled (memq (funcall get "enabled") '(:false :json-false))
                  :runs (lispm-security-runs command args))
            properties)))

(defun lispm-security--servers-of (agent prefix file servers &rest properties)
  "The items of AGENT's SERVERS, a JSON object or TOML table, from FILE.
PREFIX, if non-nil, is put before each server's name in its :id."
  (mapcar (pcase-lambda (`(,name . ,config))
            (let ((name (format "%s" name)))
              (apply #'lispm-security-server agent (if prefix (concat prefix ":" name) name)
                     name file config properties)))
          (seq-filter (lambda (entry) (and (consp entry) (listp (cdr entry)))) servers)))

(defun lispm-security-skill (agent id name file &rest properties)
  "The item of AGENT's skill NAME in FILE; ID makes its :id unique.
PROPERTIES are added to the item."
  (append (list :id (format "%s/skill/%s" agent id) :agent agent :kind 'skill :name name
                :file (abbreviate-file-name (expand-file-name file))
                :format (if (string-suffix-p ".org" file) 'org 'markdown)
                :directory (and (member (file-name-nondirectory file) '("SKILL.org" "SKILL.md"))
                                (abbreviate-file-name (file-name-directory (expand-file-name file)))))
          properties))

(defun lispm-security--skill-files (directory &optional depth)
  "The SKILL.md files under DIRECTORY, at most DEPTH directories down (2)."
  (when (file-directory-p directory)
    (let ((depth (or depth 2)) files)
      (dolist (entry (directory-files directory t "\\`[^.]"))
        (cond ((and (file-directory-p entry) (file-exists-p (expand-file-name "SKILL.md" entry)))
               (push (expand-file-name "SKILL.md" entry) files))
              ((and (file-directory-p entry) (> depth 1))
               (setq files (append (reverse (lispm-security--skill-files entry (1- depth))) files)))))
      (nreverse files))))

(defun lispm-security--markdown-skills (agent prefix directory &optional depth)
  "The items of AGENT's SKILL.md skills under DIRECTORY, ids prefixed by PREFIX."
  (mapcar (lambda (file)
            (let ((name (file-name-nondirectory (directory-file-name (file-name-directory file)))))
              (lispm-security-skill agent (if prefix (concat prefix ":" name) name) name file)))
          (lispm-security--skill-files directory depth)))

(defun lispm-security--same-directory-p (a b)
  "Non-nil if A and B are one directory, through links."
  (and (file-directory-p a) (file-directory-p b)
       (equal (file-name-as-directory (file-truename a)) (file-name-as-directory (file-truename b)))))

(defun lispm-security--project-name (root)
  "A short name of the project at ROOT."
  (file-name-nondirectory (directory-file-name (expand-file-name root))))

(defun lispm-security--projects ()
  "The roots of the projects Emacs knows, as `project-known-project-roots'."
  (require 'project)
  (seq-filter #'file-directory-p (ignore-errors (project-known-project-roots))))

;;;; LispM

(defun lispm-security--org-skills (directory)
  "The skills in DIRECTORY as LispM finds them: NAME.org, or NAME/SKILL.org.
A list of (NAME . FILE)."
  (when (file-directory-p directory)
    (append (mapcar (lambda (file) (cons (file-name-base file) file))
                    (directory-files directory t "\\`[^.].*\\.org\\'"))
            (delq nil (mapcar (lambda (dir)
                                (let ((file (expand-file-name "SKILL.org" dir)))
                                  (and (file-directory-p dir) (file-exists-p file)
                                       (cons (file-name-nondirectory dir) file))))
                              (directory-files directory t "\\`[^.]"))))))

(defun lispm-security-lispm-skill-directories ()
  "The directories LispM's agents load skills from, the user's last.
Those of `lispm-skill-directories' and the one write_skill saves in;
without LispM loaded, ~/.lispm/skills/."
  (let ((directories (mapcar (lambda (directory) (file-name-as-directory (expand-file-name directory)))
                             (if (boundp 'lispm-skill-directories)
                                 lispm-skill-directories
                               '("~/.lispm/skills/"))))
        (write (and (boundp 'lispm-write-skill-directory) lispm-write-skill-directory
                    (file-name-as-directory (expand-file-name lispm-write-skill-directory)))))
    (if (and write (not (member write directories)))
        (append directories (list write))
      directories)))

(defun lispm-security-inventory-lispm ()
  "LispM's MCP servers and skills: the user's, then each project's."
  (append
   (and (boundp 'lispm-mcp-servers)
        (mapcar (pcase-lambda (`(,name . ,config))
                  (lispm-security-server "LispM" name name nil config))
                (seq-filter (lambda (entry) (and (consp entry) (stringp (car entry)))) lispm-mcp-servers)))
   ;; A later directory's skill replaces an earlier one's of its name.
   (let (skills)
     (dolist (directory (lispm-security-lispm-skill-directories))
       (pcase-dolist (`(,name . ,file) (lispm-security--org-skills directory))
         (setf (alist-get name skills nil nil #'equal) file)))
     (mapcar (pcase-lambda (`(,name . ,file)) (lispm-security-skill "LispM" name name file))
             (sort skills (lambda (a b) (string< (car a) (car b))))))
   (mapcan (lambda (root)
             (let ((project (lispm-security--project-name root))
                   (skills (expand-file-name ".lispm/skills/" root)))
               ;; One of the user's directories is theirs, as LispM takes it.
               (unless (seq-some (lambda (directory) (lispm-security--same-directory-p directory skills))
                                 (lispm-security-lispm-skill-directories))
                 (mapcar (pcase-lambda (`(,name . ,file))
                           (lispm-security-skill "LispM" (concat project ":" name) name file
                                                 :project (abbreviate-file-name root)))
                         (lispm-security--org-skills skills)))))
           (lispm-security--projects))))

;;;; Claude Code

(defun lispm-security--claude-plugins ()
  "The directories of Claude Code's plugins installed: ((NAME . DIRECTORY) ...)."
  (let ((installed (lispm-security--json
                    (expand-file-name "plugins/installed_plugins.json" lispm-security-claude-directory))))
    (mapcan (pcase-lambda (`(,name . ,installs))
              (seq-keep (lambda (install)
                          (when-let* ((path (lispm-security--get install "installPath"))
                                      ((file-directory-p path)))
                            (cons (format "%s" name) path)))
                        (append installs nil)))
            (lispm-security--get installed "plugins"))))

(defun lispm-security--plugin-servers (agent plugin directory)
  "The items of the MCP servers of AGENT's PLUGIN, in DIRECTORY's .mcp.json."
  (let* ((file (expand-file-name ".mcp.json" directory))
         (json (lispm-security--json file)))
    (lispm-security--servers-of agent plugin file
                                (or (lispm-security--get json "mcpServers") json)
                                :plugin plugin)))

(defun lispm-security-inventory-claude ()
  "Claude Code's MCP servers and skills: the user's, its plugins', each project's."
  (let* ((config-file (expand-file-name lispm-security-claude-config-file))
         (config (lispm-security--json config-file))
         (projects (seq-filter (lambda (entry) (file-directory-p (format "%s" (car entry))))
                               (lispm-security--get config "projects")))
         (plugins (lispm-security--claude-plugins)))
    (append
     (lispm-security--servers-of "Claude Code" nil config-file (lispm-security--get config "mcpServers"))
     (mapcan (pcase-lambda (`(,root . ,data))
               (let* ((root (format "%s" root))
                      (project (lispm-security--project-name root))
                      (shared (expand-file-name ".mcp.json" root)))
                 (append
                  (lispm-security--servers-of "Claude Code" project config-file
                                              (lispm-security--get data "mcpServers")
                                              :project (abbreviate-file-name root))
                  (lispm-security--servers-of "Claude Code" project shared
                                              (lispm-security--get (lispm-security--json shared) "mcpServers")
                                              :project (abbreviate-file-name root)))))
             projects)
     (mapcan (pcase-lambda (`(,plugin . ,directory))
               (lispm-security--plugin-servers "Claude Code" plugin directory))
             plugins)
     (lispm-security--markdown-skills "Claude Code" nil
                                      (expand-file-name "skills/" lispm-security-claude-directory) 3)
     (mapcan (pcase-lambda (`(,plugin . ,directory))
               (mapcar (lambda (item) (plist-put item :plugin plugin))
                       (lispm-security--markdown-skills "Claude Code" plugin
                                                        (expand-file-name "skills/" directory))))
             plugins)
     (mapcan (pcase-lambda (`(,root . ,_))
               (let* ((root (format "%s" root))
                      (skills (expand-file-name ".claude/skills/" root)))
                 ;; The home directory's are the user's, listed already.
                 (unless (lispm-security--same-directory-p
                          skills (expand-file-name "skills/" lispm-security-claude-directory))
                   (mapcar (lambda (item) (plist-put item :project (abbreviate-file-name root)))
                           (lispm-security--markdown-skills "Claude Code" (lispm-security--project-name root)
                                                            skills)))))
             projects))))

;;;; Codex

(defun lispm-security--newest-version (directory)
  "The newest of the version directories in DIRECTORY, or nil."
  (car (sort (seq-filter #'file-directory-p (directory-files directory t "\\`[^.]"))
             (lambda (a b) (version< (file-name-nondirectory b) (file-name-nondirectory a))))))

(defun lispm-security--codex-plugins (config)
  "The directories of the plugins Codex's CONFIG enables: ((NAME . DIRECTORY) ...)."
  (let ((cache (expand-file-name "plugins/cache/" lispm-security-codex-directory)))
    (seq-keep (pcase-lambda (`(,name . ,settings))
                (when (and (eq (lispm-security--get settings "enabled") t)
                           (string-match "\\`\\(.+\\)@\\(.+\\)\\'" name))
                  (when-let* ((plugin (expand-file-name (concat (match-string 2 name) "/" (match-string 1 name))
                                                        cache))
                              ((file-directory-p plugin))
                              (version (ignore-errors (lispm-security--newest-version plugin))))
                    (cons name version))))
              (lispm-security--get config "plugins"))))

(defun lispm-security-inventory-codex ()
  "Codex's MCP servers and skills: the user's and its plugins'."
  (let* ((config-file (expand-file-name "config.toml" lispm-security-codex-directory))
         (config (lispm-security--toml config-file))
         (plugins (lispm-security--codex-plugins config))
         (disabled (seq-keep (lambda (entry)
                               (and (eq (lispm-security--get entry "enabled") :false)
                                    (lispm-security--get entry "path")))
                             (append (lispm-security--get (lispm-security--get config "skills") "config") nil))))
    (mapcar
     (lambda (item)
       (if (and (eq (plist-get item :kind) 'skill)
                (seq-find (lambda (file) (equal (abbreviate-file-name (expand-file-name file))
                                                (plist-get item :file)))
                          disabled))
           (plist-put item :disabled t)
         item))
     (append
      (lispm-security--servers-of "Codex" nil config-file (lispm-security--get config "mcp_servers"))
      (mapcan (pcase-lambda (`(,plugin . ,directory))
                (lispm-security--plugin-servers "Codex" plugin directory))
              plugins)
      (lispm-security--markdown-skills "Codex" nil (expand-file-name "skills/" lispm-security-codex-directory))
      (mapcan (pcase-lambda (`(,plugin . ,directory))
                (mapcar (lambda (item) (plist-put item :plugin plugin))
                        (lispm-security--markdown-skills "Codex" plugin (expand-file-name "skills/" directory))))
              plugins)))))

;;;; Emacs

(defun lispm-security-inventory-emacs ()
  "Emacs's packages installed."
  (when (bound-and-true-p package-alist)
    (mapcar (pcase-lambda (`(,name ,desc . ,_))
              (list :id (format "Emacs/package/%s" name) :agent "Emacs" :kind 'package
                    :name (symbol-name name)
                    :version (package-version-join (package-desc-version desc))
                    :source (if (eq (package-desc-kind desc) 'vc) "git" (package-desc-archive desc))
                    :directory (and (package-desc-dir desc)
                                    (abbreviate-file-name (package-desc-dir desc)))))
            package-alist)))

(add-hook 'lispm-security-inventory-functions #'lispm-security-inventory-lispm)
(add-hook 'lispm-security-inventory-functions #'lispm-security-inventory-claude t)
(add-hook 'lispm-security-inventory-functions #'lispm-security-inventory-codex t)
(add-hook 'lispm-security-inventory-functions #'lispm-security-inventory-emacs t)

(provide 'lispm-security-inventory)
;;; lispm-security-inventory.el ends here
