;;; lispm-security-toml.el --- Reading TOML configuration files  -*- lexical-binding: t; -*-

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

;; Codex keeps its configuration, its MCP servers among it, in TOML,
;; which Emacs has no reader for.  This reads what such a file holds,
;; as data: tables and arrays of tables, dotted and quoted keys, basic,
;; literal and multi-line strings, arrays, inline tables, numbers and
;; booleans.  Dates and times are kept as the strings they are written
;; as.  A table is an alist from its keys, strings, to their values; an
;; array is a vector.  It reads; it does not validate: a key defined
;; twice keeps its last value.

;;; Code:

(require 'seq)
(require 'subr-x)

(define-error 'lispm-security-toml-error "Not TOML")

(defun lispm-security-toml--fail (what)
  "Signal that the text at point is not TOML, as WHAT says."
  (signal 'lispm-security-toml-error (list what (line-number-at-pos))))

(defun lispm-security-toml--skip (&optional newlines)
  "Skip spaces and a comment; with NEWLINES, also line ends and blank lines."
  (while (progn (skip-chars-forward (if newlines " \t\r\n" " \t"))
                (when (eq (char-after) ?#)
                  (skip-chars-forward "^\n")
                  t))))

(defun lispm-security-toml--string (quote)
  "The string at point, opened by QUOTE, a double or a single quote."
  (let* ((multi (looking-at (make-string 3 quote)))
         (literal (eq quote ?'))
         (close (if multi (make-string 3 quote) (string quote)))
         (parts nil))
    (forward-char (if multi 3 1))
    ;; A newline right after the opening quotes is not part of the string.
    (when (and multi (looking-at "\r?\n"))
      (goto-char (match-end 0)))
    (catch 'done
      (while t
        (cond ((eobp) (lispm-security-toml--fail "unclosed string"))
              ((and (looking-at (regexp-quote close))
                    ;; """"" ends with the quotes it holds.
                    (not (and multi (looking-at (regexp-quote (concat close (string quote)))))))
               (forward-char (length close))
               (throw 'done nil))
              ((and (not multi) (eq (char-after) ?\n))
               (lispm-security-toml--fail "newline in a string"))
              ((and (not literal) (eq (char-after) ?\\))
               (forward-char 1)
               (let ((char (char-after)))
                 (forward-char 1)
                 (pcase char
                   (?n (push "\n" parts)) (?t (push "\t" parts)) (?r (push "\r" parts))
                   (?b (push "\b" parts)) (?f (push "\f" parts)) (?e (push "\e" parts))
                   (?\" (push "\"" parts)) (?\\ (push "\\" parts))
                   ((or ?u ?U)
                    (let ((digits (if (eq char ?u) 4 8)))
                      (push (string (string-to-number
                                     (buffer-substring (point) (+ (point) digits)) 16))
                            parts)
                      (forward-char digits)))
                   ((or ?\n ?\s ?\t ?\r)
                    ;; A line-ending backslash trims what follows.
                    (when multi (skip-chars-forward " \t\r\n")))
                   (_ (lispm-security-toml--fail "unknown escape")))))
              (t (push (string (char-after)) parts)
                 (forward-char 1)))))
    (apply #'concat (nreverse parts))))

(defun lispm-security-toml--key ()
  "The key at point, dotted or not: a list of strings."
  (let (parts)
    (while (progn
             (lispm-security-toml--skip)
             (push (cond ((memq (char-after) '(?\" ?'))
                          (lispm-security-toml--string (char-after)))
                         ((looking-at "[A-Za-z0-9_-]+")
                          (goto-char (match-end 0))
                          (match-string-no-properties 0))
                         (t (lispm-security-toml--fail "no key")))
                   parts)
             (lispm-security-toml--skip)
             (when (eq (char-after) ?.)
               (forward-char 1)
               t)))
    (nreverse parts)))

(defun lispm-security-toml--value ()
  "The value at point."
  (lispm-security-toml--skip)
  (pcase (char-after)
    ((or ?\" ?') (lispm-security-toml--string (char-after)))
    (?\[ (forward-char 1)
         (let (values)
           (while (progn (lispm-security-toml--skip t)
                         (not (eq (char-after) ?\])))
             (push (lispm-security-toml--value) values)
             (lispm-security-toml--skip t)
             (cond ((eq (char-after) ?,) (forward-char 1))
                   ((not (eq (char-after) ?\])) (lispm-security-toml--fail "unclosed array"))))
           (forward-char 1)
           (vconcat (nreverse values))))
    (?{ (forward-char 1)
        (let (table)
          (while (progn (lispm-security-toml--skip t)
                        (not (eq (char-after) ?})))
            (let ((key (lispm-security-toml--key)))
              (unless (eq (char-after) ?=) (lispm-security-toml--fail "no ="))
              (forward-char 1)
              (setq table (lispm-security-toml--put table key (lispm-security-toml--value))))
            (lispm-security-toml--skip t)
            (cond ((eq (char-after) ?,) (forward-char 1))
                  ((not (eq (char-after) ?})) (lispm-security-toml--fail "unclosed table"))))
          (forward-char 1)
          table))
    (_ (cond ((looking-at "true\\b") (goto-char (match-end 0)) t)
             ((looking-at "false\\b") (goto-char (match-end 0)) :false)
             ((looking-at "[-+]?\\(?:inf\\|nan\\)\\b")
              (goto-char (match-end 0)) (match-string-no-properties 0))
             ((looking-at "[-+]?0x[0-9A-Fa-f_]+")
              (goto-char (match-end 0))
              (string-to-number (string-replace "_" "" (substring (match-string 0) 2)) 16))
             ;; A date or a time, kept as written.
             ((looking-at "[0-9]\\{4\\}-[0-9][0-9]-[0-9][0-9]\\(?:[Tt ][0-9:.]+\\(?:Z\\|[-+][0-9:]+\\)?\\)?\\|[0-9][0-9]:[0-9][0-9]:[0-9.]+")
              (goto-char (match-end 0)) (match-string-no-properties 0))
             ((looking-at "[-+]?[0-9_]+\\(?:\\.[0-9_]+\\)?\\(?:[eE][-+]?[0-9_]+\\)?")
              (goto-char (match-end 0))
              (string-to-number (string-replace "_" "" (match-string 0))))
             (t (lispm-security-toml--fail "no value"))))))

(defun lispm-security-toml--put (table key value)
  "TABLE with VALUE at KEY, a list of strings naming nested tables."
  (let ((entry (assoc (car key) table)))
    (if (cdr key)
        (let ((inner (lispm-security-toml--put (and (listp (cdr entry)) (cdr entry)) (cdr key) value)))
          (if entry
              (progn (setcdr entry inner) table)
            (append table (list (cons (car key) inner)))))
      (if entry
          (progn (setcdr entry value) table)
        (append table (list (cons (car key) value)))))))

(defun lispm-security-toml--get (table key)
  "The value at KEY, a list of strings, in TABLE."
  (if (null key)
      table
    (let ((value (cdr (assoc (car key) table))))
      ;; Under an array of tables, a key names its last table.
      (when (and (vectorp value) (> (length value) 0))
        (setq value (aref value (1- (length value)))))
      (lispm-security-toml--get value (cdr key)))))

(defun lispm-security-toml--add-table (root key)
  "ROOT with a new table at the end of the array of tables at KEY."
  (let* ((parent (lispm-security-toml--get root (butlast key)))
         (array (cdr (assoc (car (last key)) parent))))
    (lispm-security-toml--put-at root key (vconcat (and (vectorp array) array) (list nil)))))

(defun lispm-security-toml--put-at (root key value)
  "ROOT with VALUE at KEY, through the last table of each array on the way."
  (if (null (cdr key))
      (lispm-security-toml--put root key value)
    (let* ((entry (assoc (car key) root))
           (inner (cdr entry)))
      (if (and (vectorp inner) (> (length inner) 0))
          (let ((copy (copy-sequence inner)))
            (aset copy (1- (length copy))
                  (lispm-security-toml--put-at (aref copy (1- (length copy))) (cdr key) value))
            (lispm-security-toml--put root (list (car key)) copy))
        (lispm-security-toml--put root (list (car key))
                                  (lispm-security-toml--put-at (and (listp inner) inner)
                                                               (cdr key) value))))))

(defun lispm-security-toml-read (text)
  "The data of the TOML TEXT: an alist from keys to values.
Signals `lispm-security-toml-error' where TEXT is not TOML."
  (with-temp-buffer
    (insert text)
    (goto-char (point-min))
    (let ((root nil) (table nil))
      (while (progn (lispm-security-toml--skip t) (not (eobp)))
        (cond ((looking-at "\\[\\[")
               (forward-char 2)
               (setq table (lispm-security-toml--key))
               (unless (looking-at "]]") (lispm-security-toml--fail "unclosed [["))
               (forward-char 2)
               (setq root (lispm-security-toml--add-table root table)))
              ((eq (char-after) ?\[)
               (forward-char 1)
               (setq table (lispm-security-toml--key))
               (unless (eq (char-after) ?\]) (lispm-security-toml--fail "unclosed ["))
               (forward-char 1)
               (unless (lispm-security-toml--get root table)
                 (setq root (lispm-security-toml--put-at root table nil))))
              (t (let ((key (lispm-security-toml--key)))
                   (unless (eq (char-after) ?=) (lispm-security-toml--fail "no ="))
                   (forward-char 1)
                   (setq root (lispm-security-toml--put-at root (append table key)
                                                           (lispm-security-toml--value))))))
        (lispm-security-toml--skip)
        (unless (or (eobp) (eq (char-after) ?\n) (eq (char-after) ?\r))
          (lispm-security-toml--fail "more on the line")))
      root)))

(defun lispm-security-toml-read-file (file)
  "The data of the TOML FILE, see `lispm-security-toml-read'."
  (lispm-security-toml-read (with-temp-buffer
                              (insert-file-contents file)
                              (buffer-string))))

(provide 'lispm-security-toml)
;;; lispm-security-toml.el ends here
