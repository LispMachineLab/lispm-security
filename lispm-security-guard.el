;;; lispm-security-guard.el --- Checking agents' tool calls as they make them  -*- lexical-binding: t; -*-

;; Copyright (C) 2026  Ryan.K

;; SPDX-License-Identifier: AGPL-3.0-or-later

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

;; A scan reports what it finds; the guard acts on it while LispM's
;; agents work.  LispM asks other programs about each tool call before
;; it runs (`lispm-tool-action-functions'), and about each MCP server's
;; tools before agents see them (`lispm-mcp-register-functions'); the
;; guard answers both, from the pins the user made by trusting servers
;; (lispm-security-pins.el):
;;
;; - The tools of a server the user has not trusted ask at every call,
;;   whatever LispM's policy says, until the user trusts the server.
;; - A tool of a trusted server that says something else than when the
;;   user trusted it, the shape of a rug pull, is kept back when LispM
;;   registers the server's tools, so that no agent reads what it says
;;   now, and its calls are denied, should the server change it while
;;   it runs.  `lispm-security-changed-tools' may have them ask instead.
;; - A toxic flow: once a session has read untrusted content (from the
;;   web or an MCP server) and private data (the user's files, memory),
;;   a call that can send data out asks, since the content may have
;;   told the model to send the data (`lispm-security-toxic-flows').
;;
;; Each answer comes with its reason, which LispM shows with the
;; approval, or tells the model with a denial.  LispM counts a check
;; that fails as one that asks: an error in the guard lets no call
;; through.  The guard can only make calls ask or be refused, never let
;; through one LispM would ask about or deny.

;;; Code:

(require 'seq)
(require 'subr-x)
(require 'lispm-security)
(require 'lispm-security-pins)

(declare-function lispm-agent-buffer "lispm-core" (agent))
(declare-function lispm-get-tool "lispm-tools" (name))
(declare-function lispm-tool-name "lispm-tools" (tool))
(declare-function lispm-tool-permission "lispm-tools" (tool))
(declare-function lispm-tool-decision "lispm-tools" (agent tool input))
(declare-function lispm-mcp-tool-origin "lispm-mcp" (tool))

(defcustom lispm-security-guard t
  "Non-nil to check the tool calls of LispM's agents as they make them.
See lispm-security-guard.el."
  :group 'lispm-security
  :type 'boolean)

(defcustom lispm-security-changed-tools 'deny
  "What becomes of a trusted server's tool that changed since it was trusted.
`deny': it is kept back when LispM registers the server's tools, and its
calls are denied; `ask': its calls ask, saying why."
  :group 'lispm-security
  :type '(choice (const :tag "Keep it back, deny its calls" deny)
                 (const :tag "Ask at each call" ask)))

(defcustom lispm-security-toxic-flows t
  "Non-nil for calls that can send data out to ask in a session that read
both untrusted content and private data.  The permission classes of
`lispm-security-untrusted-classes', `lispm-security-private-classes' and
`lispm-security-outbound-classes' say which calls are which; the tools
of MCP servers bring untrusted content and can send data out, whatever
their class."
  :group 'lispm-security
  :type 'boolean)

(defcustom lispm-security-untrusted-classes '(web)
  "Permission classes of tools whose results may be anyone's text."
  :group 'lispm-security
  :type '(repeat symbol))

(defcustom lispm-security-private-classes '(read memory)
  "Permission classes of tools whose results are the user's data."
  :group 'lispm-security
  :type '(repeat symbol))

(defcustom lispm-security-outbound-classes '(web shell exec)
  "Permission classes of tools that can send data out of this machine."
  :group 'lispm-security
  :type '(repeat symbol))

;;;; Tools of MCP servers

(defvar lispm-security-guard--registered (make-hash-table :test #'equal)
  "The tools of each server as LispM registered them last, which agents read:
server -> tools as `lispm-security-pins-tool' makes them.")

(defun lispm-security-guard--origin (tool)
  "The MCP server TOOL, a `lispm-tool', comes from, and its name there:
\(SERVER . NAME), or nil."
  (and (fboundp 'lispm-mcp-tool-origin) (lispm-mcp-tool-origin tool)))

(defun lispm-security-guard--changed (server name pin)
  "Whether SERVER's tool NAME differs from PIN, SERVER's pin.
Non-nil if PIN lacks the tool, or if the tool as LispM registered it, or
as the server lists it now, hashes otherwise."
  (let ((pinned (plist-get (cdr (assoc name (plist-get pin :tools))) :hash)))
    (or (null pinned)
        (seq-some (lambda (tools)
                    (and tools (not (equal (plist-get (cdr (assoc name tools)) :hash) pinned))))
                  (list (gethash server lispm-security-guard--registered)
                        (lispm-security-pins-listed server))))))

(defun lispm-security-guard--tool (tool)
  "What Security answers of a call of TOOL, by its server's pin; or nil."
  (when-let* ((origin (lispm-security-guard--origin tool)))
    (pcase-let* ((`(,server . ,name) origin)
                 (pin (lispm-security-pin server)))
      (cond
       ((null pin)
        (cons 'ask (format "Security: you have not trusted the tools of the MCP server %s, so \
each call asks.  Once you have read what they say, trust them in Security (M-x lispm-security, t)."
                           server)))
       ((lispm-security-guard--changed server name pin)
        (cons lispm-security-changed-tools
              (format "Security: the MCP server %s changed its tool %s since you trusted it %s.  \
Read what it says now in Security (M-x lispm-security), and trust the server again if it is right."
                      server name (format-time-string "on %Y-%m-%d" (plist-get pin :at)))))))))

(defun lispm-security-guard-register (server tools)
  "What Security answers of SERVER's TOOLS, as LispM registers them.
For `lispm-mcp-register-functions': the tools of a trusted server that
changed since it was trusted are kept back, or ask (see
`lispm-security-changed-tools')."
  (when lispm-security-guard
    (let ((listed (mapcar #'lispm-security-pins-tool tools)))
      (puthash server listed lispm-security-guard--registered)
      (when-let* ((pin (lispm-security-pin server)))
        (delq nil (mapcar (lambda (tool)
                            (and (lispm-security-guard--changed server (car tool) pin)
                                 (cons (car tool) lispm-security-changed-tools)))
                          listed))))))

;;;; Toxic flows

(defvar lispm-security-guard--seen (make-hash-table :test #'eq :weakness 'key)
  "What each agent's calls brought into its session, beyond its transcript:
agent -> plist of `untrusted' and `private' to the names of the tools.
Calls are counted when they are checked, approved or not, so that the
calls a Lisp program makes count too.")

(defvar lispm-security-guard--transcripts (make-hash-table :test #'eq :weakness 'key)
  "What each session's transcript holds: buffer -> (TICK . SEEN), SEEN as
in `lispm-security-guard--seen', as of the buffer's modification TICK.")

(defun lispm-security-guard--kinds (name)
  "What a call of the tool NAME brings into a session or can do: a list of
`untrusted', `private' and `outbound'."
  (let* ((tool (lispm-get-tool name))
         (class (and tool (lispm-tool-permission tool)))
         (mcp (or (and tool (lispm-security-guard--origin tool))
                  (string-prefix-p "mcp__" name))))
    (delq nil (list (and (or mcp (memq class lispm-security-untrusted-classes)) 'untrusted)
                    (and (memq class lispm-security-private-classes) 'private)
                    (and (or mcp (memq class lispm-security-outbound-classes)) 'outbound)))))

(defun lispm-security-guard--add (seen name)
  "SEEN, a plist as in `lispm-security-guard--seen', with the tool NAME's call."
  (dolist (kind (lispm-security-guard--kinds name) seen)
    (unless (or (eq kind 'outbound) (member name (plist-get seen kind)))
      (setq seen (plist-put seen kind (append (plist-get seen kind) (list name)))))))

(defun lispm-security-guard--transcript (buffer)
  "What the calls in the session BUFFER brought into it, as a plist as in
`lispm-security-guard--seen': those of its calls that ran, whose
results are in its context."
  (if (not (buffer-live-p buffer))
      nil
    (let ((tick (buffer-chars-modified-tick buffer))
          (cached (gethash buffer lispm-security-guard--transcripts)))
      (if (eql (car cached) tick)
          (cdr cached)
        (let (seen)
          (with-current-buffer buffer
            (save-excursion
              (save-restriction
                (widen)
                (goto-char (point-min))
                (let ((case-fold-search nil))
                  (while (re-search-forward "^\\*\\* \\(?:DONE\\|FAILED\\) \\([^ \n]+\\)" nil t)
                    (setq seen (lispm-security-guard--add seen (match-string-no-properties 1))))))))
          (puthash buffer (cons tick seen) lispm-security-guard--transcripts)
          seen)))))

(defun lispm-security-guard--names (names)
  "NAMES, a few of them, as text."
  (concat (string-join (seq-take names 3) ", ")
          (if (> (length names) 3) (format " and %d more" (- (length names) 3)) "")))

(defun lispm-security-guard--flow (agent tool)
  "What Security answers of AGENT's call of TOOL by what its session read.
The call is counted among those of AGENT's session."
  (let* ((name (lispm-tool-name tool))
         (noted (gethash agent lispm-security-guard--seen))
         (read (let ((seen (lispm-security-guard--transcript (lispm-agent-buffer agent))))
                 (dolist (kind '(untrusted private) seen)
                   (setq seen (plist-put seen kind (seq-uniq (append (plist-get seen kind)
                                                                     (plist-get noted kind)))))))))
    (puthash agent (lispm-security-guard--add noted name) lispm-security-guard--seen)
    (when (and lispm-security-toxic-flows
               (memq 'outbound (lispm-security-guard--kinds name))
               (plist-get read 'untrusted)
               (plist-get read 'private))
      (cons 'ask (format "Security: this session has read untrusted content (from %s) and private \
data (from %s), so a call that can send data out asks: the content may have told the model to send \
the data." (lispm-security-guard--names (plist-get read 'untrusted))
             (lispm-security-guard--names (plist-get read 'private)))))))

;;;; Answering LispM

(defun lispm-security-guard-tool-action (agent tool _input)
  "What Security answers of AGENT's call of TOOL, whatever its input.
For `lispm-tool-action-functions': nil, or (ask . REASON) or (deny .
REASON), by the pins of MCP servers and, for calls that can send data
out, by what AGENT's session has read."
  (when lispm-security-guard
    ;; Both are asked: the call counts among the session's either way.
    (when-let* ((answers (delq nil (list (lispm-security-guard--tool tool)
                                         (lispm-security-guard--flow agent tool)))))
      (let ((action (if (assq 'deny answers) 'deny 'ask)))
        (cons action (mapconcat #'cdr (seq-filter (lambda (answer) (eq (car answer) action)) answers)
                                "  "))))))

(add-hook 'lispm-tool-action-functions #'lispm-security-guard-tool-action)
(add-hook 'lispm-mcp-register-functions #'lispm-security-guard-register)

;;;; In a scan

(defun lispm-security-guard-check (_items)
  "Findings of whether agents' calls are checked as they make them."
  (cond
   ((not lispm-security-guard)
    (list (lispm-security-finding
           'guard-off 'medium "security" "Agents' tool calls are not checked as they make them"
           :detail "`lispm-security-guard' is off: the tools of servers you have not trusted, and \
those that changed since you did, run as LispM's policy says.  Turn it on to have them ask, or be \
refused.")))
   ((and (featurep 'lispm-tools) (not (fboundp 'lispm-tool-decision)))
    (list (lispm-security-finding
           'guard-unsupported 'medium "security" "This LispM does not let Security check tool calls"
           :detail "LispM Agent 0.3.0 and later ask Security about each tool call before it runs; \
this one runs them as its policy says.  Update LispM (Software Update) for the tools of servers you \
have not trusted, and those that changed since you did, to ask or be refused.")))))

(add-hook 'lispm-security-check-functions #'lispm-security-guard-check t)

(provide 'lispm-security-guard)
;;; lispm-security-guard.el ends here
