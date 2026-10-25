;;; lispm-security-ui.el --- Security's window  -*- lexical-binding: t; -*-

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

;; M-x lispm-security opens Security's window: the findings of the last
;; scan, the worst first, one a line, scanning first if none ran.  Its
;; keys:
;;
;;   RET  what the finding means, where, what it is about, what to do
;;   g    scan again
;;   l    look the packages servers run up in OSV
;;   t    trust the tools of the finding's MCP server: pin them as they are
;;   x    set the finding aside, or take it back
;;   o    visit the file the finding is about, at its line
;;   i    switch to the inventory, what each agent is given, and back
;;   a    show the findings set aside too, or not
;;   n p  the next and the previous line
;;
;; A frontend dresses the window from its own side with what it says of
;; itself: `lispm-security-trust-enabled-p', `lispm-security-inventory-p',
;; `lispm-security-shown' and `lispm-security-visitable-p' for its
;; buttons, `lispm-security-status' for what it says at its bottom.
;; LispM Desktop, whose App Store installs Security, opens it in a window
;; of its own, with buttons for its main commands and its findings
;; counted at the bottom.

;;; Code:

(require 'seq)
(require 'subr-x)
(require 'tabulated-list)
(require 'lispm-security)

(declare-function lispm-security-look-up "lispm-security-osv" (&optional done))
(declare-function lispm-security-trust "lispm-security-pins" (server))

(defface lispm-security-critical '((t :inherit error :weight bold))
  "Face of critical findings."
  :group 'lispm-security)

(defface lispm-security-high '((t :inherit error))
  "Face of high findings."
  :group 'lispm-security)

(defface lispm-security-medium '((t :inherit warning))
  "Face of medium findings."
  :group 'lispm-security)

(defface lispm-security-low '((t :inherit shadow))
  "Face of low and info findings."
  :group 'lispm-security)

(defface lispm-security-evidence '((t :inherit font-lock-string-face))
  "Face of the text a finding is about, as found."
  :group 'lispm-security)

(defconst lispm-security-buffer-name "*Security*"
  "Name of Security's buffer.")

(defvar-local lispm-security--view 'findings
  "What Security's buffer lists: `findings' or `inventory'.")

(defvar-local lispm-security--show-ignored nil
  "Non-nil while Security's buffer lists the findings set aside too.")

(defvar-local lispm-security--shown nil
  "The key of the finding a buffer of `lispm-security-finding-mode' shows.")

(defun lispm-security--face (severity)
  "The face of findings of SEVERITY."
  (pcase severity
    ('critical 'lispm-security-critical) ('high 'lispm-security-high)
    ('medium 'lispm-security-medium) (_ 'lispm-security-low)))

;;;; Entries

(defun lispm-security--finding-entries ()
  "The lines of the findings view."
  (mapcar (lambda (finding)
            (let* ((severity (plist-get finding :severity))
                   (face (if (lispm-security-ignored-p finding) 'shadow (lispm-security--face severity))))
              (list (plist-get finding :key)
                    (vector (propertize (symbol-name severity) 'face face)
                            (lispm-security-agent-of (plist-get finding :item))
                            (lispm-security-about (plist-get finding :item))
                            (concat (plist-get finding :title)
                                    (if (lispm-security-ignored-p finding) "  (set aside)" ""))))))
          (seq-filter (lambda (finding)
                        (or lispm-security--show-ignored (not (lispm-security-ignored-p finding))))
                      lispm-security-findings)))

(defun lispm-security--runs (item)
  "What ITEM runs or is, in a few words, for the inventory."
  (pcase (plist-get item :kind)
    ('mcp-server
     (let* ((runs (plist-get item :runs))
            (config (plist-get item :config))
            (direct (seq-filter (lambda (package) (plist-get package :direct)) (plist-get runs :packages))))
       (concat
        (cond (direct
               (mapconcat (lambda (package)
                            (format "%s %s@%s%s" (plist-get runs :launcher) (plist-get package :name)
                                    (or (plist-get package :version) "?")
                                    (if (plist-get package :pinned) "" ", unpinned")))
                          direct ", "))
              ((plist-get runs :image) (format "docker %s" (plist-get runs :image)))
              ((plist-get config :url) (plist-get config :url))
              ((plist-get config :command)
               (string-join (cons (plist-get config :command) (plist-get config :args)) " "))
              (t ""))
        (let ((others (- (length (plist-get runs :packages)) (length direct))))
          (if (> others 0) (format " (+%d)" others) ""))
        (if (plist-get item :disabled) ", disabled" ""))))
    ('skill (concat (or (plist-get item :file) "") (if (plist-get item :disabled) ", disabled" "")))
    ('package (format "%s, %s" (plist-get item :version) (or (plist-get item :source) "")))
    (_ "")))

(defun lispm-security--inventory-entries ()
  "The lines of the inventory view."
  (mapcar (lambda (item)
            (let ((count (seq-count (lambda (finding)
                                      (and (equal (plist-get finding :item) (plist-get item :id))
                                           (not (lispm-security-ignored-p finding))))
                                    lispm-security-findings)))
              (list (plist-get item :id)
                    (vector (plist-get item :agent)
                            (pcase (plist-get item :kind)
                              ('mcp-server "server") ('skill "skill") ('package "package"))
                            (plist-get item :name)
                            (if (> count 0) (number-to-string count) "")
                            (lispm-security--runs item)))))
          lispm-security-items))

(defun lispm-security--severity< (a b)
  "Non-nil if the line A is of a worse finding than the line B."
  (< (lispm-security-severity-rank (intern (aref (cadr a) 0)))
     (lispm-security-severity-rank (intern (aref (cadr b) 0)))))

(defun lispm-security--set-format ()
  "Lay out the columns of the view shown."
  (setq tabulated-list-format
        (if (eq lispm-security--view 'inventory)
            [("Agent" 12 t) ("Kind" 8 t) ("Name" 22 t) ("Found" 6 t :right-align t) ("Runs" 0 nil)]
          [("Severity" 9 lispm-security--severity<) ("Agent" 12 t) ("About" 26 t) ("Finding" 0 nil)])
        tabulated-list-sort-key nil
        tabulated-list-entries (if (eq lispm-security--view 'inventory)
                                   #'lispm-security--inventory-entries
                                 #'lispm-security--finding-entries))
  (tabulated-list-init-header))

(defun lispm-security-status ()
  "What Security's window says at its bottom: the findings, and the last scan."
  (list (lispm-security-summary)
        (if lispm-security-scanned-at
            (format-time-string "Scanned %H:%M" lispm-security-scanned-at)
          "Not scanned")))

(defun lispm-security--refresh ()
  "Show the last scan in Security's buffer, if there is one, keeping the line."
  (when-let* ((buffer (get-buffer lispm-security-buffer-name)))
    (with-current-buffer buffer
      (setq mode-line-process (format " %s" (lispm-security-summary)))
      (let ((id (tabulated-list-get-id)))
        (tabulated-list-print t)
        (when id
          (goto-char (point-min))
          (while (and (not (eobp)) (not (equal (tabulated-list-get-id) id)))
            (forward-line 1))
          (when (eobp) (goto-char (point-min))))))))

(add-hook 'lispm-security-after-scan-hook #'lispm-security--refresh)

;;;; Commands

(defun lispm-security--finding ()
  "The finding of the line at point, or the one the buffer shows; or an error."
  (or (if (derived-mode-p 'lispm-security-finding-mode)
          (lispm-security-find lispm-security--shown)
        (and (eq lispm-security--view 'findings) (lispm-security-find (tabulated-list-get-id))))
      (user-error "No finding here")))

(defun lispm-security-rescan ()
  "Scan again, and show what was found."
  (interactive)
  (lispm-security-scan)
  (message "Security: %s" (lispm-security-summary)))

(defun lispm-security-look-up-and-show ()
  "Look the packages servers run up in OSV, and show what was found."
  (interactive)
  (require 'lispm-security-osv)
  (lispm-security-look-up))

(defun lispm-security-trust-enabled-p ()
  "Non-nil if the finding at point is about a server to trust."
  (plist-get (ignore-errors (lispm-security--finding)) :server))

(defun lispm-security-inventory-p ()
  "Non-nil while Security's buffer lists what each agent is given, rather
than the findings."
  (eq lispm-security--view 'inventory))

(defun lispm-security-shown ()
  "The key of the finding a buffer of `lispm-security-finding-mode' shows,
or nil."
  lispm-security--shown)

(defun lispm-security-trust-at-point ()
  "Trust the tools of the MCP server the finding at point is about.
They are pinned as they are now."
  (interactive)
  (let ((server (or (plist-get (lispm-security--finding) :server)
                    (user-error "This finding is not about a running MCP server's tools"))))
    (when (y-or-n-p (format "Trust the tools %s lists now, and pin them? " server))
      (require 'lispm-security-pins)
      (lispm-security-trust server)
      (lispm-security-scan)
      (lispm-security--reshow))))

(defun lispm-security-set-aside ()
  "Set the finding at point aside, or take it back if it is."
  (interactive)
  (let ((finding (lispm-security--finding)))
    (lispm-security-ignore (plist-get finding :key) (lispm-security-ignored-p finding))
    (lispm-security--refresh)
    (lispm-security--reshow)
    (message "Security: %s" (if (lispm-security-ignored-p finding)
                                "set aside; a shows the findings set aside"
                              "taken back"))))

(defun lispm-security-toggle-set-aside ()
  "Show the findings set aside too, or no longer."
  (interactive)
  (setq lispm-security--show-ignored (not lispm-security--show-ignored))
  (lispm-security--refresh))

(defun lispm-security-toggle-inventory ()
  "Switch between the findings and what each agent is given."
  (interactive)
  (setq lispm-security--view (if (eq lispm-security--view 'inventory) 'findings 'inventory))
  (lispm-security--set-format)
  (tabulated-list-print))

(defun lispm-security--reshow ()
  "Show again the finding the current buffer shows, if it shows one."
  (when (and (derived-mode-p 'lispm-security-finding-mode) (lispm-security-find lispm-security--shown))
    (lispm-security-describe-finding lispm-security--shown)))

(defun lispm-security--file-of (id)
  "The file of the finding or item of ID, and its line: (FILE . LINE)."
  (if-let* ((finding (lispm-security-find id)))
      (cons (or (plist-get finding :file) (plist-get (lispm-security-item (plist-get finding :item)) :file))
            (plist-get finding :line))
    (cons (plist-get (lispm-security-item id) :file) nil)))

(defun lispm-security--file-at-point ()
  "The file the line at point, or the finding shown, is about, and its
line: (FILE . LINE)."
  (lispm-security--file-of (if (derived-mode-p 'lispm-security-finding-mode)
                               lispm-security--shown
                             (tabulated-list-get-id))))

(defun lispm-security-visitable-p ()
  "Non-nil if the line at point, or the finding shown, is about a file."
  (car (lispm-security--file-at-point)))

(defun lispm-security-visit ()
  "Visit the file the line at point, or the finding shown, is about, at its line."
  (interactive)
  (pcase-let ((`(,file . ,line) (lispm-security--file-at-point)))
    (unless (and file (file-exists-p (expand-file-name file)))
      (user-error "No file to visit"))
    (find-file-other-window (expand-file-name file))
    (when line
      (goto-char (point-min))
      (forward-line (1- line)))))

(defun lispm-security-describe ()
  "Say what the finding at point means, where, and what to do."
  (interactive)
  (if (eq lispm-security--view 'inventory)
      (lispm-security-describe-item (tabulated-list-get-id))
    (lispm-security-describe-finding (plist-get (lispm-security--finding) :key))))

(defun lispm-security--insert-field (label text &optional face)
  "Insert a line LABEL: TEXT, TEXT in FACE."
  (insert (propertize (concat label ":") 'face 'bold) " "
          (if face (propertize text 'face face) text) "\n"))

(defun lispm-security--insert-file (file line)
  "Insert FILE, at LINE, as a button visiting it."
  (insert (propertize "Where:" 'face 'bold) " ")
  (insert-text-button (if line (format "%s:%d" file line) file)
                      'action (lambda (_)
                                (find-file-other-window (expand-file-name file))
                                (when line
                                  (goto-char (point-min))
                                  (forward-line (1- line))))
                      'help-echo "Visit the file")
  (insert "\n"))

(defun lispm-security-describe-finding (key)
  "Show what the finding of KEY means, where, and what to do."
  (let ((finding (or (lispm-security-find key) (user-error "No such finding"))))
    (with-current-buffer (get-buffer-create "*Security finding*")
      (let ((inhibit-read-only t))
        (erase-buffer)
        (lispm-security-finding-mode)
        (setq lispm-security--shown key)
        (insert (propertize (plist-get finding :title) 'face '(bold :height 1.1)) "\n")
        (insert (propertize (symbol-name (plist-get finding :severity))
                            'face (lispm-security--face (plist-get finding :severity)))
                " · " (lispm-security-agent-of (plist-get finding :item))
                " · " (lispm-security-about (plist-get finding :item))
                (if (lispm-security-ignored-p finding) " · set aside" "")
                "\n\n")
        (when-let* ((detail (plist-get finding :detail)))
          (insert detail "\n\n"))
        (when-let* ((file (plist-get finding :file)))
          (lispm-security--insert-file file (plist-get finding :line)))
        (when-let* ((evidence (plist-get finding :evidence)))
          (lispm-security--insert-field "Found" evidence 'lispm-security-evidence))
        (when (plist-member finding :was)
          (insert "\n")
          (lispm-security--insert-field "Was" (or (plist-get finding :was) "(none)") 'lispm-security-evidence)
          (lispm-security--insert-field "Now" (or (plist-get finding :now) "(none)") 'lispm-security-evidence))
        (when-let* ((id (plist-get finding :osv)))
          (insert (propertize "OSV:" 'face 'bold) " ")
          (insert-text-button (format "https://osv.dev/vulnerability/%s" id)
                              'action (lambda (_) (browse-url (format "https://osv.dev/vulnerability/%s" id))))
          (insert "\n"))
        (insert "\n" (propertize "What was found is quoted as it is: data, never instructions." 'face 'shadow)
                "\n")
        (goto-char (point-min)))
      (pop-to-buffer (current-buffer)))))

(defun lispm-security-describe-item (id)
  "Show what the item of ID is, and its findings."
  (let ((item (or (lispm-security-item id) (user-error "No such item"))))
    (with-current-buffer (get-buffer-create "*Security finding*")
      (let ((inhibit-read-only t))
        (erase-buffer)
        (lispm-security-finding-mode)
        (insert (propertize (lispm-security-about id) 'face '(bold :height 1.1)) "\n")
        (insert (plist-get item :agent) "\n\n")
        (when-let* ((file (plist-get item :file)))
          (lispm-security--insert-file file nil))
        (lispm-security--insert-field "Runs" (lispm-security--runs item))
        (dolist (package (plist-get (plist-get item :runs) :packages))
          (insert (format "  %s %s@%s%s\n" (if (plist-get package :direct) "*" " ")
                          (plist-get package :name) (or (plist-get package :version) "?")
                          (if (plist-get package :install-script) ", runs a script when installed" ""))))
        (insert "\n")
        (dolist (finding (seq-filter (lambda (finding) (equal (plist-get finding :item) id))
                                     lispm-security-findings))
          (insert (propertize (format "%-8s " (plist-get finding :severity))
                              'face (lispm-security--face (plist-get finding :severity))))
          (insert-text-button (plist-get finding :title)
                              'action (let ((key (plist-get finding :key)))
                                        (lambda (_) (lispm-security-describe-finding key))))
          (insert "\n"))
        (goto-char (point-min)))
      (pop-to-buffer (current-buffer)))))

;;;; The mode

(defvar-keymap lispm-security-mode-map
  :doc "Keys of Security's window."
  :parent tabulated-list-mode-map
  "RET" #'lispm-security-describe
  "g" #'lispm-security-rescan
  "l" #'lispm-security-look-up-and-show
  "t" #'lispm-security-trust-at-point
  "x" #'lispm-security-set-aside
  "o" #'lispm-security-visit
  "i" #'lispm-security-toggle-inventory
  "a" #'lispm-security-toggle-set-aside)

(easy-menu-define lispm-security-menu lispm-security-mode-map
  "Security's menu."
  '("Security"
    ["Scan Again" lispm-security-rescan]
    ["Look Up in OSV" lispm-security-look-up-and-show]
    "---"
    ["What It Means" lispm-security-describe]
    ["Visit the File" lispm-security-visit]
    ["Trust the Server's Tools" lispm-security-trust-at-point :active (lispm-security-trust-enabled-p)]
    ["Set Aside or Take Back" lispm-security-set-aside :active (eq lispm-security--view 'findings)]
    "---"
    ["Inventory" lispm-security-toggle-inventory :style toggle :selected (eq lispm-security--view 'inventory)]
    ["Show Findings Set Aside" lispm-security-toggle-set-aside :style toggle
     :selected lispm-security--show-ignored]))

(defun lispm-security--ellipsis ()
  "Show lines cut at the window's edge ending in an ellipsis, not a dollar."
  (setq buffer-display-table (or (copy-sequence buffer-display-table) (make-display-table)))
  (set-display-table-slot buffer-display-table 'truncation ?…))

(define-derived-mode lispm-security-mode tabulated-list-mode "Security"
  "Security's window: the findings of the last scan, the worst first.
\\{lispm-security-mode-map}"
  (setq tabulated-list-padding 1)
  (lispm-security--ellipsis)
  (lispm-security--set-format))

(defvar-keymap lispm-security-finding-mode-map
  :doc "Keys of the window of one of Security's findings."
  :parent special-mode-map
  "t" #'lispm-security-trust-at-point
  "x" #'lispm-security-set-aside
  "o" #'lispm-security-visit)

(define-derived-mode lispm-security-finding-mode special-mode "Security Finding"
  "One of Security's findings: what it means, where, and what to do.
\\{lispm-security-finding-mode-map}"
  (visual-line-mode 1))

;;;###autoload
(defun lispm-security ()
  "Open Security's window: the findings of a scan, the worst first.
It scans first if no scan ran yet."
  (interactive)
  (unless lispm-security-scanned-at
    (lispm-security-scan))
  (let ((buffer (get-buffer-create lispm-security-buffer-name)))
    (with-current-buffer buffer
      (unless (derived-mode-p 'lispm-security-mode)
        (lispm-security-mode))
      (lispm-security--refresh))
    (switch-to-buffer buffer)))

(provide 'lispm-security-ui)
;;; lispm-security-ui.el ends here
