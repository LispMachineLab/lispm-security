;;; lispm-security-rules.el --- Rules: configurations and the text models read  -*- lexical-binding: t; -*-

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

;; The rules a scan checks every item against, beside what
;; lispm-security-elisp.el reads in the code of LispM's skills:
;;
;; - Servers: a package npx or uvx runs at whatever version is newest,
;;   a container image named by a tag, a command line given to a shell,
;;   a remote server reached over plain HTTP, a secret written in the
;;   configuration file, the packages that run scripts when installed,
;;   and for LispM a server whose tools are of a permission class that
;;   runs without asking.
;; - Text models read, the instructions of skills (and the files beside
;;   them) and the descriptions of tools: characters a reader does not
;;   see, among them Unicode's tags, which spell out text invisibly;
;;   comments hidden when the text is shown; long runs of blank lines
;;   pushing what follows out of view; encoded payloads; a download
;;   piped into a shell; addresses that collect what is sent to them;
;;   words to the model that a description has no reason to say; the
;;   files of credentials.
;; - The files of a skill: compiled code no one can read before it runs,
;;   and links out of the skill's directory.
;; - What agents may do without asking: LispM's default policy, Claude
;;   Code's mode that bypasses permissions, Codex's sandbox turned off.
;;
;; Rules flag what deserves a look; what a skill means to do is for the
;; user to judge, and a finding they judge harmless they set aside.

;;; Code:

(require 'seq)
(require 'subr-x)
(require 'org-src)
(require 'lispm-security)
(require 'lispm-security-inventory)

(defvar lispm-default-policy)

(defcustom lispm-security-skill-file-limit 300
  "Files of a skill's directory read at most; the rest are reported unread."
  :group 'lispm-security
  :type 'integer)

(defcustom lispm-security-text-size-limit (* 2 1024 1024)
  "Bytes of a file read at most to check its text."
  :group 'lispm-security
  :type 'integer)

(defconst lispm-security-evidence-width 160
  "Characters of evidence a finding keeps at most.")

(defun lispm-security-evidence (text)
  "TEXT as a finding's evidence: on one line, at most so wide."
  (let ((text (string-trim (replace-regexp-in-string "[ \t]*\n[ \t]*" " ⏎ " text))))
    (if (> (length text) lispm-security-evidence-width)
        (concat (substring text 0 (1- lispm-security-evidence-width)) "…")
      text)))

;;;; Text models read

(defconst lispm-security-hidden-characters
  "[\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000E0000-\U000E007F]"
  "Characters a reader does not see: zero-width ones, the controls of
bidirectional text, and Unicode's tags.")

(defconst lispm-security-collecting-hosts
  '("webhook.site" "requestbin" "pipedream.net" "interact.sh" "oast.fun" "oast.live" "oast.me" "oast.pro" "oast.site" "oast.online"
    "burpcollaborator.net" "pastebin.com" "paste.ee" "hastebin" "transfer.sh" "file.io" "0x0.st"
    "discord.com/api/webhooks" "discordapp.com/api/webhooks" "hooks.slack.com" "api.telegram.org/bot")
  "Services that collect what is sent to them, for whoever made the address.")

(defconst lispm-security-credential-files
  '("~/.ssh" ".ssh/id_" "id_rsa" "id_ed25519" "id_ecdsa" ".aws/credentials" ".netrc" ".authinfo"
    ".gnupg" ".git-credentials" ".npmrc" ".pypirc" ".docker/config.json" ".kube/config"
    ".config/gh/hosts.yml" ".codex/auth.json" "Library/Keychains" "login.keychain"
    "Login Data" "Cookies.binarycookies" "/etc/shadow" "/etc/passwd")
  "Files that hold credentials, by what their names contain.")

(defconst lispm-security-text-rules
  `((pipe-to-shell
     high "Pipes a download into a shell"
     "\\b\\(?:curl\\|wget\\)\\b[^|\n]*|[ \t]*\\(?:sudo[ \t]+\\)?\\(?:ba\\|z\\|da\\|k\\)?sh\\b\\|\\b\\(?:iex\\|Invoke-Expression\\)[ \t]*(?[ \t]*\\(?:iwr\\|irm\\|Invoke-WebRequest\\|Invoke-RestMethod\\)"
     "What runs is whatever the address serves when it runs, which no one reviewed.  Download it, \
read it, and run the copy you read, or install the tool from a package manager.")
    (collecting-address
     medium "Names a service that collects what is sent to it"
     ,(concat "\\b\\(?:" (mapconcat #'regexp-quote lispm-security-collecting-hosts "\\|") "\\)")
     "Such services receive data for whoever made the address.  A skill or a tool rarely needs \
one; it is how data leaves.")
    (ignore-instructions
     high "Tells the model to set its instructions aside"
     "\\b\\(?:ignore\\|disregard\\|forget\\|override\\)[ \t]+\\(?:all[ \t]+\\|any[ \t]+\\|the[ \t]+\\|your[ \t]+\\)?\\(?:previous\\|prior\\|above\\|earlier\\|system\\)[ \t]+\\(?:instructions\\|prompts?\\|rules\\|directions\\)"
     "Text an agent reads should describe how to do something; text that tells the model to drop \
its instructions is an injection.  Find out who wrote it before an agent loads it again.")
    (hide-from-user
     high "Tells the model to keep something from the user"
     "\\b\\(?:do[ \t]+not\\|don't\\|never\\)[ \t]+\\(?:tell\\|inform\\|notify\\|alert\\|warn\\)[ \t]+the[ \t]+user[ \t]+\\(?:that\\|about\\|of\\|what\\|you\\)\\b\\|\\b\\(?:do[ \t]+not\\|don't\\|never\\)[ \t]+\\(?:mention\\|reveal\\|show\\)[ \t]+\\(?:this\\|it\\|these\\|that\\)[ \t]+\\(?:\\(?:step\\|instruction\\|tool\\|call\\)s?[ \t]+\\)?to[ \t]+the[ \t]+user\\|\\bwithout[ \t]+\\(?:asking\\|telling\\|informing\\|notifying\\|alerting\\)[ \t]+the[ \t]+user\\|\\b\\(?:keep\\|hide\\)[ \t]+\\(?:this\\|it\\|these\\)[ \t]+\\(?:secret\\|hidden\\)[ \t]+from[ \t]+the[ \t]+user"
     "Doing things behind the user's back is what an attack asks of an agent; an honest skill has \
no reason to.")
    (model-tags
     medium "Speaks to the model in tags of its own"
     "<\\(?:IMPORTANT\\|important\\|SYSTEM\\|system\\|instructions\\|INSTRUCTIONS\\|admin\\|ADMIN\\)>"
     "Tags such as <IMPORTANT> in a tool's description or a skill are a common shape of tool \
poisoning: words addressed to the model, which the user does not read.")
    (credential-file
     medium "Names a file of credentials"
     ,(regexp-opt lispm-security-credential-files)
     "Keys, tokens and passwords live there.  A skill or a tool that reads them can send them \
anywhere it reaches."))
  "Rules checked against text: (RULE SEVERITY TITLE REGEXP DETAIL).")

(defun lispm-security--line (position)
  "The line number of POSITION in the current buffer."
  (1+ (count-lines (point-min) (save-excursion (goto-char position) (line-beginning-position)))))

(defun lispm-security--line-text ()
  "The text of the line at point."
  (buffer-substring-no-properties (line-beginning-position) (line-end-position)))

(defun lispm-security--shown (text)
  "TEXT with the characters a reader does not see named, and tags spelt out."
  (replace-regexp-in-string
   lispm-security-hidden-characters
   (lambda (char)
     (let ((code (string-to-char char)))
       (if (<= #xE0000 code #xE007F)
           (if (<= #xE0020 code #xE007E) (string (- code #xE0000)) "")
         (format "<U+%04X>" code))))
   text t t))

(defun lispm-security-text-findings (item text &optional file line what markdown lesser)
  "Findings of the text rules in TEXT, of ITEM, written in FILE from LINE.
WHAT names the text in titles, such as \"the instructions\"; MARKDOWN
non-nil checks what Markdown hides when shown too.  LESSER non-nil is
for text the model does not read as instructions, such as a skill's
scripts: naming a file of credentials there is a low finding."
  (let ((line (or line 1)) findings)
    (with-temp-buffer
      (insert text)
      (let ((at (lambda (position) (+ line -1 (lispm-security--line position))))
            (title (lambda (title) (if what (format "%s (%s)" title what) title)))
            (case-fold-search nil))
        ;; Hidden characters, a finding a line.
        (goto-char (point-min))
        (let ((count 0))
          (while (and (< count 5) (re-search-forward lispm-security-hidden-characters nil t))
            (let ((tags (save-excursion
                          (goto-char (line-beginning-position))
                          (re-search-forward "[\U000E0000-\U000E007F]" (line-end-position) t))))
              (push (lispm-security-finding
                     (if tags 'hidden-tags 'hidden-characters) 'high item
                     (funcall title (if tags "Spells out text in invisible Unicode tags"
                                      "Holds characters a reader does not see"))
                     :file file :line (funcall at (point))
                     :evidence (lispm-security-evidence (lispm-security--shown (lispm-security--line-text)))
                     :detail (if tags
                                 "Unicode's tag characters show as nothing, yet a model reads them as the \
letters they encode, shown here spelt out: instructions the user never sees."
                               "Zero-width characters and the controls of bidirectional text change \
what a reader sees from what the model reads, shown here by their code points."))
                    findings)
              (cl-incf count)
              (forward-line 1))))
        ;; The rules of regexps, five findings a rule at most.
        (pcase-dolist (`(,rule ,severity ,rule-title ,regexp ,detail) lispm-security-text-rules)
          (goto-char (point-min))
          (let ((count 0)
                (case-fold-search (not (eq rule 'model-tags))))
            (while (and (< count 5) (re-search-forward regexp nil t))
              ;; A phrase quoted is spoken of, as a warning against it is.
              (unless (and (memq rule '(ignore-instructions hide-from-user))
                           (memq (char-before (match-beginning 0)) '(?\" ?“ ?‘ ?\' ?\` ?«)))
                (push (lispm-security-finding
                       rule (if (and lesser (eq rule 'credential-file)) 'low severity)
                       item (funcall title rule-title)
                       :file file :line (funcall at (match-beginning 0))
                       :evidence (lispm-security-evidence (lispm-security--line-text))
                       :detail detail)
                      findings)
                (cl-incf count))
              (forward-line 1))))
        ;; Encoded payloads.
        (goto-char (point-min))
        (when (re-search-forward "\\(?:[A-Za-z0-9+/]\\{4\\}\\)\\{60,\\}\\(?:[A-Za-z0-9+/]\\{2,3\\}=\\{0,2\\}\\)?\\|\\b[0-9a-fA-F]\\{240,\\}\\b" nil t)
          (unless (save-excursion
                    (goto-char (match-beginning 0))
                    (looking-back "data:image/[a-z+]+;base64,\\|sha[0-9]+-\\|integrity[\"']?[:=][ \t]*[\"']" (line-beginning-position)))
            (push (lispm-security-finding
                   'encoded-payload 'medium item (funcall title "Carries a long encoded payload")
                   :file file :line (funcall at (match-beginning 0))
                   :evidence (lispm-security-evidence (match-string 0))
                   :detail "Base64 or hex this long hides what it holds from whoever reads the text: \
code, a binary, instructions.  Decode it to see what it is, and why it is there.")
                  findings)))
        ;; Blank lines pushing the rest out of view.
        (goto-char (point-min))
        (when (re-search-forward "\\(?:^[ \t]*\n\\)\\{200,\\}" nil t)
          (push (lispm-security-finding
                 'padding 'medium item (funcall title "Pushes what follows out of view")
                 :file file :line (funcall at (match-end 0))
                 :evidence (format "%d blank lines, then: %s"
                                   (count-lines (match-beginning 0) (match-end 0))
                                   (lispm-security-evidence
                                    (buffer-substring-no-properties
                                     (match-end 0) (min (point-max) (+ (match-end 0) 200)))))
                 :detail "Hundreds of blank lines keep what comes after them from reviewers and from \
scanners that read only the start; what follows is shown here.")
                findings))
        ;; What Markdown does not show.
        (when markdown
          (goto-char (point-min))
          (let ((count 0))
            (while (and (< count 5) (re-search-forward "<!--\\(\\(?:.\\|\n\\)*?\\)-->" nil t))
              (when (string-match-p "[[:alpha:]].\\{15,\\}" (match-string 1))
                (push (lispm-security-finding
                       'hidden-comment 'low item (funcall title "Holds a comment Markdown does not show")
                       :file file :line (funcall at (match-beginning 0))
                       :evidence (lispm-security-evidence (match-string 1))
                       :detail "Shown as Markdown, the comment disappears; the model reads it all the \
same.  Read what it says.")
                      findings)
                (cl-incf count)))))))
    (nreverse findings)))

;;;; Skills

(defun lispm-security-org-blocks (text)
  "The blocks of the skill TEXT LispM evaluates: ((LINE . CODE) ...).
Those of emacs-lisp marked :lispm load, unescaped as org does, LINE the
first line of CODE in TEXT: the blocks `lispm-skills--blocks' takes."
  (with-temp-buffer
    (insert text)
    (goto-char (point-min))
    (let ((case-fold-search t) blocks)
      (while (re-search-forward "^[ \t]*#\\+begin_src[ \t]+emacs-lisp\\([^\n]*\\)\n" nil t)
        (let ((args (match-string 1))
              (start (point)))
          (when (re-search-forward "^[ \t]*#\\+end_src" nil t)
            (when (string-match-p ":lispm[ \t]+load" args)
              (push (cons (line-number-at-pos start)
                          (org-unescape-code-in-string
                           (buffer-substring-no-properties start (match-beginning 0))))
                    blocks)))))
      (nreverse blocks))))

(defun lispm-security-org-instructions (text)
  "The skill TEXT without the code LispM evaluates, its lines kept blank.
Its code is read as Lisp, in lispm-security-elisp.el."
  (with-temp-buffer
    (insert text)
    (pcase-dolist (`(,line . ,code) (lispm-security-org-blocks text))
      (goto-char (point-min))
      (forward-line (1- line))
      (dotimes (_ (1- (length (split-string code "\n"))))
        (delete-region (point) (line-end-position))
        (insert "·")
        (forward-line 1)))
    (buffer-string)))

(defconst lispm-security-compiled-files
  "\\.\\(?:pyc\\|pyo\\|elc\\|eln\\|so\\|dylib\\|dll\\|exe\\|class\\|jar\\|wasm\\|node\\|o\\|a\\|bin\\)\\'"
  "Files of compiled code, which no one reads before they run.")

(defconst lispm-security-media-files
  "\\.\\(?:png\\|jpe?g\\|gif\\|webp\\|ico\\|bmp\\|tiff?\\|svg\\|woff2?\\|ttf\\|otf\\|eot\\|pdf\\|mp[34]\\|wav\\|ogg\\|webm\\|mov\\)\\'"
  "Files of images, fonts and sound: not text, and not code.")

(defun lispm-security--python-cache-p (file)
  "Non-nil if FILE is Python's compiled copy of a source beside it, made after it.
Python writes those itself, in __pycache__, when the source runs."
  (and (string-match "/__pycache__/\\([^/.]+\\)\\.[^/]+\\.pyc\\'" file)
       (let ((source (expand-file-name (concat (match-string 1 file) ".py")
                                       (file-name-directory (directory-file-name (file-name-directory file))))))
         (and (file-exists-p source)
              (not (time-less-p (file-attribute-modification-time (file-attributes file))
                                (file-attribute-modification-time (file-attributes source))))))))

(defun lispm-security--text-file-p (file)
  "Non-nil if FILE holds text: it has no NUL in its first bytes."
  (with-temp-buffer
    (set-buffer-multibyte nil)
    (insert-file-contents-literally file nil 0 8000)
    (not (search-forward "\0" nil t))))

(defun lispm-security-read-text (file)
  "The text of FILE, at most `lispm-security-text-size-limit' bytes of it."
  (with-temp-buffer
    (insert-file-contents file nil 0 lispm-security-text-size-limit)
    (buffer-string)))

(defun lispm-security-skill-files (item)
  "The files of skill ITEM: its file, and the others of its directory."
  (let ((file (expand-file-name (plist-get item :file))))
    (if-let* ((directory (plist-get item :directory)))
        (cons file (seq-remove (lambda (other) (or (equal other file)
                                                   (and (file-directory-p other) (not (file-symlink-p other)))))
                               (sort (directory-files-recursively
                                      (expand-file-name directory) "" t
                                      (lambda (subdirectory)
                                        (not (member (file-name-nondirectory subdirectory) '(".git" ".hg")))))
                                     #'string<)))
      (list file))))

(defun lispm-security--skill-findings (item)
  "The findings of the rules for skill ITEM and the files of its directory."
  (let* ((files (lispm-security-skill-files item))
         (directory (and (plist-get item :directory)
                         (file-name-as-directory (file-truename (plist-get item :directory)))))
         (main (car files))
         findings)
    (when (> (length files) lispm-security-skill-file-limit)
      (push (lispm-security-finding
             'many-files 'low item (format "Holds %d files; the first %d were checked"
                                           (length files) lispm-security-skill-file-limit)
             :file (plist-get item :directory)
             :detail "A skill seldom needs so many.  The rest were not read.")
            findings)
      (setq files (seq-take files lispm-security-skill-file-limit)))
    (dolist (file files)
      (let ((name (abbreviate-file-name file))
            (beside (not (equal file main))))
        (cond
         ((and directory (file-symlink-p file)
               (not (string-prefix-p directory (file-truename file))))
          (push (lispm-security-finding
                 'link-out 'high item "Links to a file outside the skill"
                 :file name :evidence (abbreviate-file-name (file-truename file))
                 :detail "What the link reaches is read by the skill as its own, wherever it is: a \
file of the user's could be taken along, or replaced.")
                findings))
         ((file-directory-p file))
         ((string-match-p lispm-security-media-files file))
         ((and (string-match-p lispm-security-compiled-files file)
               (not (lispm-security--python-cache-p file)))
          (push (lispm-security-finding
                 'compiled-file 'high item "Holds compiled code"
                 :file name
                 :detail "Compiled code cannot be read before it runs, and need not do what its \
source, if any, says.  A skill should ship its source only.")
                findings))
         ((not (file-regular-p file)))
         ((string-match-p lispm-security-compiled-files file))
         ((not (lispm-security--text-file-p file))
          (push (lispm-security-finding
                 'binary-file 'low item "Holds a binary file"
                 :file name
                 :detail "Not text, so not checked.  Make sure it is what its name says, such as an \
image the skill shows.")
                findings))
         ;; LispM's Lisp is read as code, in lispm-security-elisp.el.
         ((and (eq (plist-get item :format) 'org) (string-suffix-p ".el" file)))
         (t (let ((text (lispm-security-read-text file)))
              (setq findings
                    (append findings
                            (lispm-security-text-findings
                             item
                             (if (and (not beside) (eq (plist-get item :format) 'org))
                                 (lispm-security-org-instructions text)
                               text)
                             name 1
                             (if beside (file-name-nondirectory file) "the instructions")
                             (string-match-p "\\.md\\'" file)
                             (and beside (not (string-match-p "\\.\\(?:md\\|org\\|txt\\)\\'" file)))))))))))
    findings))

;;;; Servers

(defconst lispm-security-secret-patterns
  '("\\`gh[pousr]_[A-Za-z0-9]\\{30,\\}" "\\`github_pat_[A-Za-z0-9_]\\{40,\\}"
    "\\`sk-\\(?:ant-\\|proj-\\)?[A-Za-z0-9_-]\\{20,\\}" "\\`xox[abposr]-[A-Za-z0-9-]\\{10,\\}"
    "\\`AKIA[0-9A-Z]\\{16\\}\\'" "\\`AIza[0-9A-Za-z_-]\\{35\\}\\'" "\\`[sr]k_live_[0-9A-Za-z]\\{20,\\}"
    "\\`glpat-[0-9A-Za-z_-]\\{20,\\}" "\\`npm_[0-9A-Za-z]\\{30,\\}" "\\`hf_[0-9A-Za-z]\\{30,\\}"
    "-----BEGIN [A-Z ]*PRIVATE KEY-----"
    "\\`eyJ[A-Za-z0-9_-]\\{10,\\}\\.[A-Za-z0-9_-]\\{10,\\}\\.[A-Za-z0-9_-]\\{10,\\}"
    "\\`\\(?:Bearer\\|Basic\\|token\\)[ \t]+[A-Za-z0-9._~+/=-]\\{16,\\}")
  "What secrets look like: tokens of the services that issue most of them.")

(defconst lispm-security-secret-names
  "\\(?:TOKEN\\|SECRET\\|PASSWORD\\|PASSWD\\|API_?KEY\\|ACCESS_?KEY\\|PRIVATE_?KEY\\|CREDENTIALS?\\|AUTHORIZATION\\)"
  "What the names of variables and headers holding secrets contain.")

(defun lispm-security-secret-p (name value)
  "Non-nil if VALUE, named NAME (or nil), looks like a secret written out.
A reference to one elsewhere, such as ${TOKEN}, $TOKEN or op://..., is not."
  (and (stringp value)
       (>= (length value) 8)
       (not (string-match-p "\\`\\(?:\\$\\|%\\|env:\\|op://\\|file:\\|keychain:\\|/\\|~/\\|<\\|\\[\\)" value))
       (not (string-match-p "\\${\\|{{" value))
       (or (seq-some (lambda (pattern) (string-match-p pattern value)) lispm-security-secret-patterns)
           (and name
                (let ((case-fold-search t)) (string-match-p lispm-security-secret-names name))
                (not (string-match-p "\\`\\(?:true\\|false\\|yes\\|no\\|[0-9]+\\)\\'" value))
                (not (string-match-p "[ \t]" value))))))

(defun lispm-security-redacted (secret)
  "SECRET, shown without giving it away: its first characters and its length."
  (format "%s… (%d characters)" (substring secret 0 (min 4 (length secret))) (length secret)))

(defun lispm-security--server-secrets (config)
  "The secrets written out in server CONFIG: ((WHERE . VALUE) ...)."
  (let (secrets)
    (pcase-dolist (`(,name . ,value) (plist-get config :env))
      (when (lispm-security-secret-p name value)
        (push (cons (format "its environment variable %s" name) value) secrets)))
    (pcase-dolist (`(,name . ,value) (plist-get config :headers))
      (when (lispm-security-secret-p name value)
        (push (cons (format "its header %s" name) value) secrets)))
    (when (lispm-security-secret-p "token" (plist-get config :token))
      (push (cons "its token" (plist-get config :token)) secrets))
    (let ((args (plist-get config :args)) previous)
      (dolist (arg args)
        (cond ((string-match "\\`--?\\([A-Za-z_-]+\\)=\\(.+\\)\\'" arg)
               (when (lispm-security-secret-p (match-string 1 arg) (match-string 2 arg))
                 (push (cons (format "its argument %s" (match-string 1 arg)) (match-string 2 arg)) secrets)))
              ((lispm-security-secret-p (and previous (string-prefix-p "-" previous) previous) arg)
               (push (cons "an argument" arg) secrets)))
        (setq previous arg)))
    (when-let* ((url (plist-get config :url))
                ((string-match "[?&]\\([A-Za-z_]*\\(?:key\\|token\\|secret\\)[A-Za-z_]*\\)=\\([^&]+\\)" url))
                ((lispm-security-secret-p (match-string 1 url) (match-string 2 url))))
      (push (cons "its URL" (match-string 2 url)) secrets))
    (nreverse secrets)))

(defun lispm-security-init-files ()
  "The files where the user's Emacs configuration is written."
  (seq-uniq
   (seq-filter
    (lambda (file) (and file (file-regular-p file)))
    (append (list user-init-file (bound-and-true-p custom-file) (bound-and-true-p early-init-file))
            (directory-files user-emacs-directory t "\\`[^.].*\\.el\\'")
            (let ((lisp (expand-file-name "lisp/" user-emacs-directory)))
              (and (file-directory-p lisp) (directory-files lisp t "\\`[^.].*\\.el\\'")))))))

(defun lispm-security--written-in (secret files)
  "The first of FILES whose text holds SECRET, or nil."
  (seq-find (lambda (file)
              (with-temp-buffer
                (insert-file-contents file nil 0 lispm-security-text-size-limit)
                (search-forward secret nil t)))
            files))

(defun lispm-security--readable-by-others-p (file)
  "Non-nil if users other than its owner may read FILE."
  (let ((modes (file-modes file)))
    (and modes (/= 0 (logand modes #o044)))))

(defun lispm-security--secret-findings (item)
  "Findings of the secrets written out in server ITEM's configuration."
  (let ((init-files (and (equal (plist-get item :agent) "LispM") (lispm-security-init-files))))
    (delq nil
          (mapcar
           (pcase-lambda (`(,where . ,secret))
             (let ((file (if init-files
                             (lispm-security--written-in secret init-files)
                           (and (plist-get item :file) (expand-file-name (plist-get item :file))))))
               ;; LispM's value may come from auth-source: only one written
               ;; in a file of the configuration is reported.
               (when (and file (file-exists-p file))
                 (lispm-security-finding
                  'secret-in-config 'medium item
                  (format "Writes a secret out, in %s" where)
                  :file (abbreviate-file-name file)
                  :evidence (lispm-security-redacted secret)
                  :detail (concat
                           "Whatever reads the file has the secret: the agents among them, and every \
backup and copy of the file.  Keep it in a store of secrets (auth-source, the keychain) or in an \
environment variable the server is given, and revoke this one if the file was ever shared."
                           (if (lispm-security--readable-by-others-p file)
                               "  The file can be read by other users of this computer, too."
                             ""))))))
           (lispm-security--server-secrets (plist-get item :config))))))

(defun lispm-security--local-url-p (url)
  "Non-nil if URL is of this machine."
  (string-match-p "\\`[a-z]+://\\(?:localhost\\|127\\.[0-9.]+\\|\\[::1\\]\\|0\\.0\\.0\\.0\\)\\(?:[:/]\\|\\'\\)" url))

(defun lispm-security--server-findings (item)
  "Findings of the rules for MCP server ITEM's configuration and what it runs."
  (let* ((config (plist-get item :config))
         (runs (plist-get item :runs))
         (url (plist-get config :url))
         (disabled (plist-get item :disabled))
         (file (plist-get item :file))
         findings)
    (unless disabled
      (dolist (package (plist-get runs :packages))
        (when (and (plist-get package :direct) (not (plist-get package :pinned)))
          (let ((named (plist-get package :named))
                (version (plist-get package :version)))
            (push (lispm-security-finding
                   'unpinned-package 'medium item
                   (format "Runs %s at whatever version is newest" (plist-get package :name))
                   :file file
                   :evidence (string-join (plist-get runs :specs) " ")
                   :detail (concat
                            (format "%s runs the package as %s, so each start may run a version \
published since: the next release, or one an attacker who took over the package published.  "
                                    (plist-get runs :launcher)
                                    (if named (format "\"%s\"" named) "named, without a version"))
                            (if version
                                (format "It ran %s last.  Name that version: %s, and update it on purpose."
                                        version
                                        (if (equal (plist-get package :ecosystem) "npm")
                                            (format "%s@%s" (plist-get package :name) version)
                                          (format "%s==%s" (plist-get package :name) version)))
                              "Name the version it should run.")))
                  findings))))
      (let ((scripts (seq-filter (lambda (package) (plist-get package :install-script))
                                 (plist-get runs :packages))))
        (when scripts
          (push (lispm-security-finding
                 'install-scripts 'low item
                 (if (cdr scripts)
                     (format "Installs %d packages that run scripts when installed" (length scripts))
                   (format "Installs %s, which runs a script when installed"
                           (plist-get (car scripts) :name)))
                 :file file
                 :evidence (mapconcat (lambda (package)
                                        (format "%s@%s" (plist-get package :name) (plist-get package :version)))
                                      scripts ", ")
                 :detail "npm runs these scripts when it installs the packages, before the server \
starts, with everything the user can do.  They are how most malicious packages strike.")
                findings)))
      (when (and (eq (plist-get runs :launcher) 'docker) (not (plist-get runs :pinned)))
        (push (lispm-security-finding
               'unpinned-image 'medium item
               (format "Runs the image %s by a tag" (plist-get runs :image))
               :file file :evidence (plist-get runs :image)
               :detail "A tag can be moved to another image at any time.  Name the image by its \
digest, IMAGE@sha256:..., which always names the same one.")
              findings))
      (when (eq (plist-get runs :launcher) 'shell)
        (let ((line (or (plist-get runs :line) "")))
          (push (lispm-security-finding
                 'shell-server 'low item "Starts through a shell"
                 :file file :evidence (lispm-security-evidence line)
                 :detail "A shell's command line runs whatever its variables and the PATH make of \
it.  Make sure the line does only what it should.")
                findings)
          (setq findings (append findings (lispm-security-text-findings item line file nil "its command line")))))
      (when (and (stringp url) (string-prefix-p "http://" url) (not (lispm-security--local-url-p url)))
        (push (lispm-security-finding
               'plain-http 'medium item "Is reached over plain HTTP"
               :file file :evidence url
               :detail "Without TLS, anyone on the way reads the calls and their answers, tokens \
included, and can change them.  Use https://.")
              findings))
      (when-let* (((equal (plist-get item :agent) "LispM"))
                  (permission (plist-get config :permission))
                  ((boundp 'lispm-default-policy))
                  ((eq (alist-get permission lispm-default-policy) 'auto)))
        (push (lispm-security-finding
               'server-runs-unasked 'medium item
               (format "Its tools are of class %s, which runs without asking" permission)
               :evidence (format ":permission %s" permission)
               :detail "Every call of the server's tools runs at once, whatever it does; its tools \
are as trusted as LispM's own.  Leave out :permission, for the class mcp, which asks.")
              findings)))
    (append (nreverse findings) (lispm-security--secret-findings item))))

;;;; What agents may do without asking

(defun lispm-security--policy-findings ()
  "Findings of what the agents' settings let them do without asking."
  (let (findings)
    (when (boundp 'lispm-default-policy)
      (pcase-dolist (`(,class . ,what) '((exec . "evaluate any Lisp in Emacs")
                                         (shell . "run shell commands")
                                         (write . "change files")
                                         (mcp . "call MCP servers' tools")
                                         (web . "fetch from the web")))
        (when (eq (alist-get class lispm-default-policy) 'auto)
          (push (lispm-security-finding
                 'policy-auto (if (memq class '(exec shell)) 'medium 'low) "LispM/settings"
                 (format "LispM's agents %s without asking" what)
                 :evidence (format "(%s . auto) in lispm-default-policy" class)
                 :detail "Then nothing stops an agent that read the wrong page, file or tool \
description from acting on it.  Set the class to ask in `lispm-default-policy', and allow what you \
trust per call.")
                findings))))
    (let* ((file (expand-file-name "settings.json" lispm-security-claude-directory))
           (settings (lispm-security--json file)))
      (when (equal (lispm-security--get (lispm-security--get settings "permissions") "defaultMode")
                   "bypassPermissions")
        (push (lispm-security-finding
               'policy-bypass 'medium "Claude Code/settings" "Claude Code bypasses its permissions"
               :file (abbreviate-file-name file) :evidence "\"defaultMode\": \"bypassPermissions\""
               :detail "Claude Code then runs every tool call without asking.  Use another mode, \
or run it so only in a sandbox.")
              findings)))
    (let* ((file (expand-file-name "config.toml" lispm-security-codex-directory))
           (config (lispm-security--toml file)))
      (when (equal (lispm-security--get config "sandbox_mode") "danger-full-access")
        (push (lispm-security-finding
               'policy-bypass (if (equal (lispm-security--get config "approval_policy") "never") 'medium 'low)
               "Codex/settings" "Codex runs without its sandbox"
               :file (abbreviate-file-name file) :evidence "sandbox_mode = \"danger-full-access\""
               :detail "Codex's commands then reach the whole computer and the network.  Use \
workspace-write, which keeps them to the project.")
              findings)))
    (nreverse findings)))

;;;; Checking

(defun lispm-security-rules-check (items)
  "The findings of the rules for ITEMS, and of the agents' settings."
  (append
   (mapcan (lambda (item)
             (pcase (plist-get item :kind)
               ('mcp-server (lispm-security--server-findings item))
               ('skill (lispm-security--skill-findings item))))
           items)
   (lispm-security--policy-findings)))

(add-hook 'lispm-security-check-functions #'lispm-security-rules-check)

(provide 'lispm-security-rules)
;;; lispm-security-rules.el ends here
