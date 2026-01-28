# ------------------------------------
# 1. Εισαγωγή απαραίτητων βιβλιοθηκών:
# ------------------------------------

from __future__ import annotations  # Για χρήση μοντέρων λειτουργιών στα type hints.
import streamlit as st              # Για δημιουργία web εφαρμογών.
import subprocess                   # Για εκτέλεση εξωτερικών εντολών (CLI εργαλείων).
import tempfile                     # Για δημιουργία προσωρινών αρχείων.
import os                           # Για διάφορες λειτουργίες του συστήματος - διαχείριση των αρχείων.
import json                         # Για επεξεργασία JSON δεδομένων (π.χ. ανάγνωση/γραφή).
import pandas as pd                 # Για επεξεργασία και ανάλυση δεδομένων (π.χ δημιουργία πινάκων).
import ast                          # Για ανάλυση και επεξεργασία Python κώδικα μέσω AST (Abstract Syntax Tree).
import logging                      # Για καταγραφή συμβάντων, σφαλμάτων και παρακολούθηση της ροής εκτέλεσης.
from typing import Any              # Type hints για καλύτερη αναγνωσιμότητα κώδικα.
from dotenv import load_dotenv      # Για φόρτωση μεταβλητών περιβάλλοντος (π.χ. API keys) από αρχεία μορφής .env
from radon.complexity import cc_visit           # Αφορά στον εντοπισμό μπλοκ κώδικα και στην κυκλική πολυπλοκότητα (Cyclomatic Complexity).
from radon.metrics import mi_visit              # Αφορά στον υπολογισμό του δείκτη συντηρησιμότητας (Maintainability Index).

load_dotenv()                       # Φορτώνει το αρχείο .env για να διαβαστεί το API key αργότερα.

# ------------------
# 2. Ρύθμιση logging
# ------------------

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",)
format="%(asctime)s [%(levelname)s] %(name)s - %(messages)s",
logger = logging.getLogger("sast_tool")

# ---------------------------------------------------
# 3. Βοηθητική συνάρτηση για τα CLI-based εργαλεία
# ---------------------------------------------------

def run_subprocess_json(cmd: list[str],
                         tool_label: str,
                         ok_returncodes: tuple[int, ...] = (0,1),
                         install_hint: str | None = None) -> dict[str,Any]:
    """
    Εκτελεί μια εντολή CLI και αναλύει την έξοδο JSON. Η συνάρτηση διαχειρίζεται αυτόματα
    τα σφάλματα εκτέλεσης  και αποκωδικοποίησης JSON. Επιστρέφει ένα τυποποιημένο λεξικό
    με τη μορφή:
    {"ok": boolean, αν η εκτέλεση του εργαλείου ήταν επιτυχής.
     "error": μήνυμα σφάλματος σε μορφή string ή None αν υπήρξε πρόβλημα.
     "results": Any, καθώς πρόκειται για τα ευρήματα ως raw δεδομένα JSON  του εργαλείου.
     "extras": Λεξικό (dict) για επιπλέον στοιχεία εάν χρειαστεί.
    }
    tool_label: Όνομα του εργαλείου για την εμφάνιση των μηνυμάτων (π.χ. "Bandit")
    install_hint: Προαιρετική οδηγία εγκατάστασης (π.χ. "pip install bandit")
    """
    # Προσπάθεια εκτέλεσης της εντολής cmd μέσω subprocess.run
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace")
    except FileNotFoundError:           # Σε περίπτωση που η εντολή δεν βρεθεί στο PATH.
        error_msg = f"Το εργαλείο {tool_label} δεν βρέθηκε στο σύστημα."
        if install_hint:
            error_msg += f"Εγκαταστήστε το με την εντολή: {install_hint}"
        return {
            "ok": False,
            "error": error_msg,                      
            "results": [],
            "extras": {}}
        
    except Exception as exc:            # Σε περίπτωση οπιουδήποτε άλλου απρόοπτου σφάλματος κατά την εκτέλεση της subprocess.
        logger.exception("Σφάλμα κατά την εκτέλεση subprocess για %s: %s", tool_label, cmd)
        return {
            "ok": False,
            "error": (f"Σφάλμα κατά την εκτέλεση του {tool_label}: {exc}"),                                            
            "results": [],
            "extras": {}}
        
    # Καθαρισμός των εξόδων από τις stdout και stderr.
    stdout_str: str = (result.stdout or "").strip()
    stderr_str: str = (result.stderr or "").strip()
    
    # Επιτρεπτοί κωδικοί επιστροφής : 0 (επιτυχία) και 1 (ευρήματα)
    if result.returncode not in ok_returncodes:
        err = stderr_str or f"Μη αναμενόμενος κωδικός επιστροφής από {tool_label}: {result.returncode}"
        return {
            "ok": False, 
            "error": err, 
            "results": [], 
            "extras": {}}
    
    # Εάν δεν υπάρχει καθόλου έξοδος στο stdout, αυτό είναι ένδειξη κάποιου προβλήματος.
    if not stdout_str:
        return{
               "ok": False,
               "error": stderr_str or f"Κενή έξοδος από το εργαλείο {tool_label}.",
               "results": [],
               "extras": {}}                    
               
    # Προσπάθεια μετατροπής της JSON εξόδου σε λεξικό ή λίστα της Python.
    try:
        data = json.loads(stdout_str)
    except json.JSONDecodeError as exc:
        logger.exception("Αδυναμία ανάγνωσης της JSON εξόδου από %s: %s", tool_label, stdout_str[:200])
        return{"ok": False,
               "error": f"Αδυναμία ανάγνωσης της JSON εξόδου του {tool_label}: {exc}",
               "results": [],
               "extras": {}}
    # Επιτυχής εκτέλεση οπότε επιστρέφονται τα δεδομένα.
    return {"ok": True, "error": None, "results": data, "extras": {}}
   

# ---------------------------------------------------------------------------
# 4. Ορισμός συνάρτησης για εκτέλεση βιβλιοθήκης Bandit σε κώδικα Python.
# ---------------------------------------------------------------------------

def run_bandit_on_code(code: str) -> dict[str, Any]:
    """
    Τρέχει τη βιβλιοθήκη Bandit σε string Python κώδικα και επιστρέφει λεξικό (dict) 
    με τα ακόλουθα κλειδιά (αποτελέσματα):
         1. ok: boolean αν η εκτέλεση ήταν επιτυχής.
         2. error: μήνυμα σφάλματος σε μορφή string ή None αν προκύψει πρόβλημα.
         3. results: λίστα με τα ευρήματα της ανάλυσης (list[dict]).
         4. metrics: Λεξικο με τυχόν μετρικές που δίνει το Bandit (dict).
    """
    # Αρχικοποίηση μεταβλητής για το προσωρινό αρχείο.
    temp_file_path: str | None = None
    
    try:   

    # Δημιουργία προσωρινού αρχείου για αποθήκευση του κώδικα Python.
        with tempfile.NamedTemporaryFile(delete=False, suffix=".py", mode="w", encoding="utf-8") as temp_file:
            temp_file.write(code)                                # Εγγραφή του κώδικα στο προσωρινό αρχείο.
            temp_file_path = temp_file.name                      # Αποθήκευση της διαδρομής του προσωρινού αρχείου.  

        # Ορισμός εντολής CLI για τη Bandit με:
        # -f json: μορφή εξόδου JSON
        # -q: Quiet mode για λιγότερα μηνύματα στην κονσόλα.
        cmd = ["bandit", "-f", "json", "-q", temp_file_path]

        # Κλήση της βοηθητικής συνάρτησης για εκτέλεση της εντολής.
        result = run_subprocess_json(cmd,
                                     tool_label="Bandit",
                                     install_hint="pip install Bandit", 
                                     ok_returncodes=(0, 1))  

        # Αν η εκτέλεση απέτυχε, επιστρέφεται το σφάλμα.
        if not result["ok"]:
            return{
                "ok": False,
                "error": result["error"],
                "results": [],
                "metrics": {}}
        # Ανάκτηση της JSON εξόδου επιστρέφοντας λεξικό με τα ευρήματα του Bandit.
        data = result["results"] or {}
        return {
            "ok": True,
            "error": None,
            "results": data.get("results", []),
            "metrics": data.get("metrics", {})}
    # Αυτό το μπλοκ εκτελείται πάντα ώστε να διαγραφεί το προσωρινό αρχείο και να μην γεμίζει η μνήμη.
    finally:      
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except OSError:
                logger.warning("Αποτυχία διαγραφής προσωρινού αρχείου Bandit.")                                  
                                     
# ----------------------------------------------------------------------------
# 5. Ορισμός συνάρτησης για εκτέλεση της βιβλιοθήκης Semgrep σε κώδικα Python.
# ----------------------------------------------------------------------------

def run_semgrep_on_code(code: str) -> dict[str, Any]:
    """
    Τρέχει τη βιβλιοθήκη Semgrep σε string Python κώδικα χρησιμοποιώντας το ruleset p/python
    και επιστρέφει λεξικό (dict) με τα ακόλουθα κλειδιά (αποτελέσματα):
         1. ok: boolean αν η εκτέλεση ήταν επιτυχής.
         2. error: μήνυμα σφάλματος ή None αν υπήρξε πρόβλημα.
         3. results: λίστα με τα ευρήματα της ανάλυσης (list[dict]).
    """
    # Αρχικοποίηση μεταβλητής για το προσωρινό αρχείο.
    temp_file_path: str | None = None
    
    try:   
        # Δημιουργία προσωρινού αρχείου για αποθήκευση του κώδικα Python.
        with tempfile.NamedTemporaryFile(delete=False, suffix=".py", mode="w", encoding="utf-8") as temp_file:
            temp_file.write(code)                                # Εγγραφή του κώδικα στο προσωρινό αρχείο.
            temp_file_path = temp_file.name                      # Αποθήκευση της διαδρομής του προσωρινού αρχείου.  

        # Ορισμός εντολής CLI για τη Semgrep με:
        # --config auto: αυτόματη εύρεση κανόνων.
        # --json: μορφή εξόδου JSON        
        cmd = ["semgrep", "scan", "--config", "p/security-audit", 
               "--config", "p/owasp-top-ten", "--config", "p/python", "--json", temp_file_path]

        # Κλήση της βοηθητικής συνάρτησης για εκτέλεση της εντολής.
        result = run_subprocess_json(cmd,
                                     tool_label="Semgrep",
                                     install_hint="pip install Semgrep",
                                     ok_returncodes=(0, 1)) 

        # Αν η εκτέλεση απέτυχε, επιστρέφεται το σφάλμα.
        if not result["ok"]:
            return{
                "ok": False,
                "error": result["error"],
                "results": []}
        
        # Ανάκτηση της JSON εξόδου επιστρέφοντας λεξικό με τα ευρήματα του Semgrep.
        data = result["results"] or {}
        return {
            "ok": True,
            "error": None,
            "results": data.get("results", [])}
    # Αυτό το μπλοκ εκτελείται πάντα ώστε να διαγραφεί το προσωρινό αρχείο και να μην γεμίζει η μνήμη.
    finally:        
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except OSError:
                logger.warning("Αποτυχία διαγραφής προσωρινού αρχείου Semgrep.")   

# ------------------------------------------------------------------------------------------------------
# 6. Ορισμός συνάρτησης για εκτέλεση της βιβλιοθήκης Pylint - στατικής ανάλυσης ποιότητας κώδικα Python.
# ------------------------------------------------------------------------------------------------------

def run_pylint_on_code(code: str) -> dict[str, Any]:
    """
    Τρέχει τη βιβλιοθήκη Pylint σε string Python κώδικα και επιστρέφει λεξικό (dict) 
    με τα ακόλουθα κλειδιά (αποτελέσματα):
         1. ok: boolean αν η εκτέλεση ήταν επιτυχής.
         2. error: μήνυμα σφάλματος σε μορφή string ή None αν υπήρξε πρόβλημα.
         3. results: λίστα με μηνύματα της Pylint (list[dict]).
         4. score: συνολική αξιολόγηση κώδικα (string ή None).
    Χρησιμοποιείται το CLI του Pylint με έξοδο σε μορφή JSON.
    """
    # Αρχικοποίηση μεταβλητής για το προσωρινό αρχείο.
    temp_file_path: str | None = None
    
    try:   
        # Δημιουργία προσωρινού αρχείου για αποθήκευση του κώδικα Python.
        with tempfile.NamedTemporaryFile(delete=False, suffix=".py", mode="w", encoding="utf-8") as temp_file:
            temp_file.write(code)                                # Εγγραφή του κώδικα στο προσωρινό αρχείο.
            temp_file_path = temp_file.name                      # Αποθήκευση της διαδρομής του προσωρινού αρχείου.  

        # Ορισμός εντολής CLI για τη Semgrep με:
        # --json: μορφή εξόδου JSON   
        # --score: υπολογισμός βαθμολογίας κώδικα.     
        cmd = ["pylint", "-f", "json", "--score=y", temp_file_path]

        # Κλήση της βοηθητικής συνάρτησης για εκτέλεση της εντολής.
        result = run_subprocess_json(cmd,
                                     tool_label="Pylint",
                                     install_hint="pip install Pylint",
                                     ok_returncodes=(0, 1, 2, 4, 8, 16)) 

        # Αν η εκτέλεση απέτυχε, επιστρέφεται το σφάλμα.
        if not result["ok"]:
            return{
                "ok": False,
                "error": result["error"],
                "results": [],
                "score": None}
        
        # Ανάκτηση της JSON εξόδου επιστρέφοντας λεξικό με τα ευρήματα του Semgrep.
        data = result["results"]
        messages: list[dict[str, Any]] = []          # Λίστα για αποθήκευση των επιμέρους μηνυμάτων του Pylint (warnings, errors).
        score_text: str | None = None                # Κείμενο ή αριθμός με τη συνολική βαθμολογία.

        # Η μορφή εξόδου του JSON της Pylint ανάλογα με την έκδοση μπορεί να επιστρέψει είτε λίστα, είτε λεξικό.
        # Αν η έξοδος είναι λίστα JSON αντικειμένων.
        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):                  # Αν το στοιχείο δεν είναι λεξικό, παραλείπεται για να αποφευχθεί σφάλμα.
                    continue
                if "type" in item and "message" in item:        # Αν το λεξικό έχει τα κλειδιά "type" και "message", θεωρείται κανονικό 
                    messages.append(item)                       # μήνυμα Pylint, οπότε προστίθεται στη λίστα των μηνυμάτων.
                if "score" in item and score_text is None:      # Αν το λεξικό περιέχει κλειδί "score" και δεν έχει ήδη οριστεί τιμή στο score_text,
                    score_text = str(item.get("score"))         # τότε αποθηκεύεται στο score_text η βαθμολογία ως string.

        # Αν η έξοδος είναι λεξικό με κλειδί messages (πιθανή περίπτωση σε κάποιες εκδόσεις).
        elif isinstance(data, dict):
            for msg in data.get("messages", []):                # Λήψη της λίστας μηνυμάτων από το κλειδί "messages" (αν δεν υπάρχει, λαμβάνεται κενή λίστα).
                if isinstance(msg, dict):                       # Προστίθενται μόνο τα μηνύματα που είναι λεξικά.
                    messages.append(msg)
            if "score" in data:                                 # Αν το λεξικό περιέχει κλειδί "score",
                score_text = str(data.get("score"))             # τότε αποθηκεύεται στο score_text η βαθμολογία ως string.

        # Επιστροφή των αποτελεσμάτων.
        return {
            "ok": True,
            "error": None,
            "results": messages,
            "score": score_text}      
    # Αυτό το μπλοκ εκτελείται πάντα ώστε να διαγραφεί το προσωρινό αρχείο και να μην γεμίζει η μνήμη.
    finally:        
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except OSError:
                logger.warning("Αποτυχία διαγραφής προσωρινού αρχείου Pylint.")   

# ---------------------------------------------------------------------------
# 7. Ορισμός συνάρτησης για εκτέλεση της βιβλιοθήκης Radon ως προς τον έλεγχο 
# της κυκλωματικής πολυπλοκότητας (CC) και δείκτη συντηρησιμότητας (ΜΙ).
# ---------------------------------------------------------------------------

def run_radon_on_code(code: str) -> dict[str,Any]:
    """
    Τρέχει τη βιβλιοθήκη Radon σε string Python κώδικα και επιστρέφει λεξικό (dict) 
    με τα ακόλουθα κλειδιά (αποτελέσματα):
         1. ok: boolean αν η εκτέλεση ήταν επιτυχής.
         2. error: μήνυμα σφάλματος σε μορφή string ή None αν υπήρξε πρόβλημα.
         3. results: λίστα με μπλοκ κώδικα και την κυκλωματική πολυπλοκότητά τους.
         4. mi: δείκτης συντηρησιμότητας (float ή None).
    Χρησιμοποιεί το API του Radon (cc_visit, cc_rank, mi_visit).
    """
   
    try:        
        cc_blocks = cc_visit(code)                    # Επιστροφή λίστας με μπλοκ κώδικα (functions, methods, classes) και την κυκλωματική πολυπλοκότητά τους.
        mi_score = mi_visit(code, multi=False)        # Υπολογισμός του δείκτη συντηρησιμότητας (Maintainability Index). 
    except Exception as exc:
        return {                           
            "ok": False,
            "error": f"Σφάλμα κατά την ανάλυση με τη βιβλιοθήκη Radon: {exc}",
            "results": [],
            "mi": None
        }
    issues: list[dict[str, Any]]= []                                       # Λίστα για αποθήκευση των αποτελεσμάτων.
    # Για κάθε μπλοκ επιστρέφονται name, type, lineno, complexity (CC) και rank (A-F)
    for block in cc_blocks:
        issues.append({                                                    # Προσθήκη λεξικού με τα στοιχεία του μπλοκ κώδικα στη λίστα αποτελεσμάτων.
            "Όνομα": getattr(block, "name", ""),
            "Τύπος": getattr(block, "kind", getattr(block, "type", "")),
            "Γραμμή": getattr(block, "lineno", None),
            "CC": getattr(block, "complexity", None),
            "Βαθμίδα": getattr(block, "rank", None)})
        
    # Επιστροφή των αποτελεσμάτων.
    return {
        "ok": True,
        "error": None,
        "results": issues,
        "mi": float(mi_score) if mi_score is not None else None}

# -----------------------------------------------------------------------------------
# 8. Ορισμός global λιστών με λέξεις κλειδιά για χρήση στον custom AST αναλυτή κώδικα.
# -----------------------------------------------------------------------------------


# Λέξεις κλειδιά που υποδηλώνουν πιθανές "ευαίσθητες" μεταβλητές (π.χ. password, token κλπ).
SUSPECT_SECRET_KEYWORDS: list[str] = [
                           "password", 
                           "passwd", 
                           "pwd", 
                           "secret", 
                           "token", 
                           "key", 
                           "apikey",
                           "api_key", 
                           "auth", 
                           "credential"] 

# Συνηθισμένα ονόματα logging συναρτήσεων (logging.info, logger.error κλπ).
LOGGING_FUNCTION_NAMES : list[str] = [
                          "print", 
                          "logging.debug",
                          "logging.info", 
                          "logging.warning", 
                          "logging.error", 
                          "logging.critical", 
                          "logging.exception", 
                          "logging.log"]

# --------------------------------------------------------------------------------
# 9. Ορισμός συνάρτησης εκτέλεσης custom AST αναλυτή κώδικα με χρήση SecurityVisitor.
# --------------------------------------------------------------------------------

class SecurityVisitor(ast.NodeVisitor):
    """
    Προσαρμοσμένος επισκέπτης (Visitor) AST για ανίχνευση:        
        1. hard-coded μυστικών σε μεταβλητές με ύποπτα ονόματα,
        2. logging ενδεχομένως ευαίσθητων μεταβλητών που μοιάζουν με μυστικά (π.χ. password),
        3. χρήση επικίνδυνων συναρτήσεων όπως eval/exec,
        4. κλήσεων subprocess χωρίς κατάλληλο χειρισμό εισόδο, π.χ. χρήση shell=True (πιθανό command injection).
    """
    def __init__(self)-> None:
        super().__init__()
        self.issues: list[dict[str, Any]] = []              # Λίστα για αποθήκευση των ευρημάτων ασφαλείας.

    def visit_Assign(self, node: ast.Assign) -> None:
        """
        Ελέγχει αναθέσεις (Assign) για hard-coded μυστικά σε ύποπτες μεταβλητές.

        """
        # Έλεγχος για ανάθεση τιμών σε μεταβλητές με ύποπτα ονόματα όπως password, token κλπ.
        for target in node.targets:
            if isinstance(target, ast.Name):         # Αν ο στόχος της ανάθεσης είναι απλή μεταβλητή.       
                var_name = target.id
                lower_name = var_name.lower()        # Μετατροπή του ονόματος σε πεζά για ευκολότερο έλεγχο.
                # Έλεγχος αν το όνομα της μεταβλητής περιέχει κάποια από τις ύποπτες λέξεις-κλειδιά.
                if any(k in lower_name for k in SUSPECT_SECRET_KEYWORDS):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):          # Έλεγχος αν η τιμή που ανατίθεται είναι σταθερή συμβολοσειρά (hard-coded string).
                        value_str = node.value.value
                        value_preview = (value_str if len(value_str) <= 50 else value_str[:47] + "...")     # Προεπισκόπηση της τιμής (περιορισμένη σε 50 χαρακτήρες).
                        # Καταγραφή του ευρήματος.
                        self.issues.append({
                            "Είδος": "Hard-coded secret",
                            "Όνομα": var_name,
                            "Γραμμή": node.lineno,
                            "Λεπτομέρειες": f"Ανάθεση σταθερής συμβολοσειράς σε μεταβλητή με όνομα '{var_name}'.",
                            "Τιμή (Προεπισκόπηση)": value_preview,
                            })

        # Συνέχεια της επίσκεψης στα υπόλοιπα nodes.
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """
        Ελέγχει κλήσεις συναρτήσεων (Call) για logging ευαίσθητων μεταβλητών 
        και χρήση επικίνδυνων συναρτήσεων.
        
        """
        func_name: str | None = None                    # Όνομα συνάρτησης που καλείται.
        full_name: str | None = None                    # Όνομα αντικειμένου αν η συνάρτηση είναι μέθοδος (π.χ. logger.info -> logger).
        if isinstance(node.func, ast.Name):             # Περίπτωση απλής συνάρτησης μορφής func(), π.χ. eval().
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):      # Περίπτωση μεθόδου μορφής obj.method(), π.χ. logger.info().
            func_name = node.func.attr
            if isinstance(node.func.value, ast.Name):   # Αν το value είναι Name, τότε η κλήση θα είναι μορφής "logging.info".
                full_name = f"{node.func.value.id}.{node.func.attr}"
            else:
                full_name = node.func.attr

        # Έλεγχος για logging ευαίσθητων μεταβλητών.
        if full_name in LOGGING_FUNCTION_NAMES:
            for arg in node.args:                       # Έλεγχος όλων των ορισμάτων της συνάρτησης.
                if isinstance(arg, ast.Name):           # Αν το όρισμα είναι όνομα μεταβλητής, εξετάζεται αν περιέχει ευαίσθητα δεδομένα.                    
                    lower_name = arg.id.lower()
                    if any(k in lower_name for k in SUSPECT_SECRET_KEYWORDS):
                        self.issues.append(
                            {"Είδος": "Logging ενδεχομένως ευαίσθητης μεταβλητής",
                             "Όνομα": arg.id,
                             "Γραμμή": node.lineno,
                             "Λεπτομέρειες": (f"Κλήση logging συνάρτησης '{full_name or func_name}'με όρισμα "
                             f"τη μεταβλητή '{arg.id}', η οποία ίσως περιέχει ευαίσθητα δεδομένα."),
                             "Τιμή (Προεπισκόπηση)": ""})    

        # Έλεγχος για κλήσεις subprocess με shell=True (πιθανό command injection).
        basic_obj_name = None
        # έλεγχος εάν καλείται κάτι από το module subprocess.
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            basic_obj_name = node.func.value.id           # όπως π.χ. subprocess.            
        if basic_obj_name == "subprocess" and func_name in ("run", "Popen", "call", "check_call", "check_output"):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:       
                    self.issues.append(
                            {"Είδος": "Πιθανό Command Injection",
                             "Όνομα": f"{basic_obj_name}.{func_name}",
                             "Γραμμή": node.lineno,
                             "Λεπτομέρειες": (f"Κλήση της συνάρτησης '{basic_obj_name}.{func_name}' με παράμετρο shell=True, "
                                              "που μπορεί να οδηγήσει σε command injection εάν τα ορίσματα δεν έχουν ελεγχθεί σωστά."),
                            "Τιμή (Προεπισκόπηση)": ""})
                    
        # Γενική επισήμανση για χρήση επικίνδυνων συναρτήσεων eval/exec.
        if func_name in ("eval", "exec"):
            self.issues.append(
                {"Είδος": "Χρήση επικίνδυνης συνάρτησης",
                 "Όνομα": func_name,
                 "Γραμμή": node.lineno,
                 "Λεπτομέρειες": (f"Κλήση της συνάρτησης '{func_name}', η οποία μπορεί να οδηγήσει σε "
                 "εκτέλεση κακόβουλου κώδικα ή έγχυση κώδικα."),
                 "Τιμή (Προεπισκόπηση)": ""})

        self.generic_visit(node)                         # Συνέχεια της επίσκεψης στα υπόλοιπα nodes.
        
# Ορισμός συνάρτησης για εκτέλεση του custom AST αναλυτή.
def run_custom_ast_analysis(code: str) -> dict[str, Any]:
    """
    Εκτελεί τον προσαρμοσμένο AST αναλυτή (SecurityVisitor) σε string Python κώδικα και 
    επιστρέφει λεξικό (dict) με τα ακόλουθα κλειδιά (αποτελέσματα):
         1. ok: boolean αν η εκτέλεση ήταν επιτυχής.
         2. error: μήνυμα σφάλματος σε μορφή string ή None αν υπήρξε πρόβλημα.
         3. results: λίστα με τα ευρήματα της ανάλυσης (list[dict]).

    """
    try:
        tree = ast.parse(code)                  # Μετατροπή του κώδικα σε AST tree.
    except SyntaxError as exc:                  # Σε περίπτωση σφάλματος σύνταξης στον κώδικα.
            return {
                "ok": False,
                "error": f"Σφάλμα σύνταξης κατά την ανάλυση AST: {exc}",
                "results": []}
    
    visitor = SecurityVisitor()                # Δημιουργία instance του επισκέπτη.
    visitor.visit(tree)                        # Επίσκεψη του AST με τον επισκέπτη.

    # Επιστροφή των αποτελεσμάτων.
    return {
        "ok": True,
        "error": None,
        "results": visitor.issues}  

# --------------------------------------------------------------------------------         
# 9. Συνάρτηση για δημιουργία συγκεντρωτικής αναφοράς (report) ευρημάτων ανάλυσης.
# --------------------------------------------------------------------------------

def create_libr_findings_report(                          # Δημιουργία συγκεντρωτικής αναφοράς (report) με ενιαίο κείμενο.
    filename: str,
    code: str,
    df_bandit: pd.DataFrame | None,
    df_semgrep: pd.DataFrame | None,
    df_pylint: pd.DataFrame | None,
    df_radon: pd.DataFrame | None,
    df_custom_ast: pd.DataFrame | None,
    bandit_metrics: dict[str, Any] | None,
    pylint_score: str | None,
    radon_mi: float | None,
)-> str:
    """
    Δημιουργεί μία συγκεντρωτική αναφορά (report) με ενιαίο κείμενο ου περιλαμβάνει:
    1. Τον πηγαίο κώδικα που αναλύθηκε.
    2. Τα ευρήματα από όλες τις βιβλιοθήκες που επιλέχθηκαν για ανάλυση κώδικα.
    3. Τις μετρικές Bandit/Pylint/Radon κλπ.
    
    """
    lines: list[str] = []                           # Λίστα για αποθήκευση των γραμμών της αναφοράς.

    lines.append("=== Συγκεντρωτική Αναφορά AST-based SAST εργαλείου ανάλυσης κώδικα Python ===")
    lines.append("")
    lines.append(f"Όνομα αρχείου: {filename}")
    lines.append("")

    lines.append("=== Πηγαίος Κώδικας Python που αναλύθηκε ===")
    lines.append(code)
    lines.append("")

    # Ενότητα βιβλιοθήκης Bandit.
    lines.append("=== Ευρήματα Bandit ===")
    if df_bandit is not None and not df_bandit.empty:
        lines.append(df_bandit.to_csv(index=False))
    else:
        lines.append("Δεν υπάρχουν ευρήματα από τη Bandit ή η βιβλιοθήκη δεν εκτελέστηκε.")
    lines.append("")
    if bandit_metrics:
        lines.append(f"Μετρικές Bandit: {bandit_metrics}")
        lines.append("")
    
    # Ενότητα βιβλιοθήκης Semgrep.
    lines.append("=== Ευρήματα Semgrep ===")
    if df_semgrep is not None and not df_semgrep.empty:
        lines.append(df_semgrep.to_csv(index=False))
    else:
        lines.append("Δεν υπάρχουν ευρήματα από τη Semgrep ή η βιβλιοθήκη δεν εκτελέστηκε.")
    lines.append("")

    # Ενότητα βιβλιοθήκης Pylint.
    lines.append("=== Ευρήματα Pylint ===")
    if df_pylint is not None and not df_pylint.empty:
        lines.append(df_pylint.to_csv(index=False))
    else:
        lines.append("Δεν υπάρχουν ευρήματα από την Pylint ή η βιβλιοθήκη δεν εκτελέστηκε.")
    if pylint_score:
        lines.append(f"Συνολική βαθμολογία Pylint: {pylint_score}")
    lines.append("")

    # Ενότητα βιβλιοθήκης Radon.
    lines.append("=== Ευρήματα Radon ===")
    if df_radon is not None and not df_radon.empty:
        lines.append(df_radon.to_csv(index=False))
    else:
        lines.append("Δεν υπάρχουν ευρήματα από τη Radon ή η βιβλιοθήκη δεν εκτελέστηκε.")
    if radon_mi is not None:
        lines.append(f"Δείκτης Συντηρησιμότητας (MI) Radon: {radon_mi}")
    lines.append("")

    # Ενότητα προσαρμοσμένου (Custom) AST αναλυτή.
    lines.append("=== Ευρήματα Custom AST Αναλυτή (SecurityVisitor) ===")
    if df_custom_ast is not None and not df_custom_ast.empty:
        lines.append(df_custom_ast.to_csv(index=False))
    else:
        lines.append("Δεν υπάρχουν ευρήματα από τον Custom AST Αναλυτή ή η ανάλυση δεν εκτελέστηκε.")
    lines.append("")

    return "\n".join(lines)                         # Επιστροφή της αναφοράς ως ενιαίο κείμενο.

# -----------------------------------------------------------------
# 10. Ορισμός συνάρτησης για δημιουργία σύνοψης των ευρημάτων ανάλυσης.
# -----------------------------------------------------------------

def create_analysis_summary(
    filename: str,
    code: str,
    df_bandit: pd.DataFrame | None,
    df_semgrep: pd.DataFrame | None,
    df_pylint: pd.DataFrame | None,
    df_radon: pd.DataFrame | None,
    df_custom_ast: pd.DataFrame | None,
    bandit_metrics: dict[str, Any] | None,
    pylint_score: str | None,
    radon_mi: float | None,
    max_code_lines: int = 100,
    max_rows_per_tool: int = 40) -> str:
    """
    Δημιουργεί μία σύντομη σύνοψη της ανάλυσης (summary) για χρήση ως prompt στο ChatGPT,
    η οποία περιλαμβάνει:
    1. Μικρό preview του πηγαίου κώδικα (max_code_lines).
    2. Περίληψη των ευρημάτων από κάθε βιβλιοθήκη (μέχρι max_rows_per_tool εγγραφές.)

    """
    lines: list[str] = []                                           # Λίστα για αποθήκευση των γραμμών της σύνοψης.

    lines.append("=== Σύνοψη ευρημάτων ανάλυσης του AST-based SAST εργαλείου για κώδικα Python ===")
    lines.append(f"Όνομα αρχείου: {filename}")
    lines.append("")

    # Προσθήκη μόνο των πρώτων γραμμών κώδικα (max_code_lines) ως preview.
    code_lines = code.splitlines()                                  # Διαχωρισμός του κώδικα σε γραμμές.
    preview_code = "\n".join(code_lines[:max_code_lines])           # Λήψη των πρώτων max_code_lines γραμμών.
    lines.append(f"Προεπισκόπηση πηγαίου κώδικα (πρώτες {max_code_lines} γραμμές):")
    lines.append("```python")                                       # Έναρξη μπλοκ κώδικα με επισήμανση Python.
    lines.append(preview_code)
    lines.append("```")                                             # Τέλος μπλοκ κώδικα.
    lines.append("")

    # Εσωτερική βοηθητική συνάρτηση για προσθήκη σύντομης περίληψης ευρημάτων,
    # ενός Dataframe βιβλιοθήκης του εργαλείου.
    def add_df_summary(title: str, df: pd.DataFrame | None) -> None:
        lines.append(f"--- Ευρήματα από {title} ---")
        if df is not None and not df.empty:        
            df_preview = df.head(max_rows_per_tool)                     # Λήψη των πρώτων max_rows_per_tool γραμμών.
            lines.append(df_preview.to_csv(index=False))                # Προσθήκη των ευρημάτων σε μορφή CSV.
        else:
            lines.append(f"Δεν υπάρχουν ευρήματα από το {title} ή η βιβλιοθήκη δεν εκτελέστηκε.")
        lines.append("")

    # Προσθήκη περίληψης ευρημάτων Bandit.
    add_df_summary("Bandit:", df_bandit)                                 
    if bandit_metrics:          
        lines.append(f"Μετρικές Bandit: {bandit_metrics}")
    lines.append("")

    # Προσθήκη περίληψης ευρημάτων Semgrep.
    add_df_summary("Semgrep:", df_semgrep)

    # Προσθήκη περίληψης ευρημάτων Pylint.
    add_df_summary("Pylint:", df_pylint)
    if pylint_score:
        lines.append(f"Συνολική βαθμολογία Pylint: {pylint_score}")
    lines.append("")

    # Προσθήκη περίληψης ευρημάτων Radon.
    add_df_summary("Radon:", df_radon)
    if radon_mi is not None:
        lines.append(f"Δείκτης Συντηρησιμότητας (MI) Radon: {radon_mi}")
    lines.append("")

    # Προσθήκη περίληψης ευρημάτων Custom AST Αναλυτή.
    add_df_summary("Custom AST Αναλυτής (SecurityVisitor):", df_custom_ast)

    return "\n".join(lines)                                                # Επιστροφή της σύνοψης ως ενιαίο κείμενο.

# ------------------------------------------------------------------------------
# 11. Ενσωμάτωση OpenAI-ChatGPT και ορισμός συνάρτησεων για αρχικοποίηση του client της OpenAI και κλήση του ChatGPT API 
# ώστε να παρέχει προτάσεις βελτίωσης της ασφάλειας του κώδικα.
# ------------------------------------------------------------------------------

try:
    from openai import OpenAI           # Εισαγωγή client της OpenAI για κλήση κάποιου μοντέλου του ChatGPT από το εργαλείο.
except Exception:
    OpenAI = None

# Ορισμός συνάρτησης για αρχικοποίηση του client της OpenAI
def _init_openai_client() -> Any | None:
    """
   Δημιουργεί client της OpenAI αν υπάρχει έγκυρο API key.
   Το API key διαβάζεται από τη μεταβλητή περιβάλλοντος OPENAI_API_KEY.

    """
    if OpenAI is None:
        return None                     # Η βιβλιοθήκη openai δεν είναι εγκατεστημένη.
    
    # Ανάγνωση API key από τη μεταβλητή του περιβάλλοντος.
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None                     # Δεν έχει οριστεί το API key.
    
    try:
        return OpenAI(api_key=api_key)  # Δημιουργία instance του OPENAI client.
    except Exception:
        logger.exception("Αποτυχία αρχικοποίησης OpenAI client.")
        return None
    
# Αρχικοποίηση του client στην εκκίνηση του script.
openai_client = _init_openai_client()
    
# Ορισμός συνάρτησης για κλήση του ChatGPT API
def ask_chatgpt_for_sec_advice(summary_text: str) -> tuple[bool,str]:
    """
    Καλεί το ChatGPT (OpenAI API) με είσοδο δεδομένων τη σύνοψη της ανάλυσης
    και επιστρέφει tuple (ok, text ή μήνυμα σφάλματος).

    """
    # Αν δεν υπάρχει διαθέσιμος client, ενημερώνεται ο χρηστης σχετικά.
    if openai_client is None:
        return (False, "Δεν έχει οριστεί έγκυρο openai_api_key στο περιβάλλον ή δεν έγινε αρχικοποίηση του OpenAI client."
                " Παρακαλώ ορίστε τη μεταβλητή περιβάλλοντος για το API key και ξαναδοκιμάστε.")
    
    # System prompt: περιγραφή του ρόλου που θα έχει το ChatGPT.
    system_prompt = (
        "Είσαι ειδικός στην ασφαλή ανάπτυξη λογισμικού σε Python "
        "και στη στατική ανάλυση κώδικα. Θα λάβεις μία σύνοψη που αναγράφει "
        "τα ευρήματα της ανάλυσης σε Python, με τη χρήση ενός AST-based "
        "εργαλείου SAST, που περιλαμβάνει ευπάθειες, κακές πρακτικές και "
        "μετρικές ποιότητας.Αφού διαβάσεις σχολαστικά το περιεχόμενο της "
        "σύνοψης, για κάθε εύρημα θα πρέπει να δώσεις ασφαλείς πρακτικές "
        "και τεχνικά ακριβείς οδηγίες για το πώς μπορεί να τροποποιηθεί "
        " ο κώδικας με στόχο την ασφάλεια και την καθαροτητά του.\n\n"
        "Η απάντησή σου να είναι δομημένη σε ενότητες, με ύφος σοβαρό,"
        "και επιστημονικό παρέχοντας τη βασική θεωρία και χρήσιμες πληροφορίες.")
    
    # User prompt: Ενσωματώνουμε τη σύνοψη των ευρημάτων που δημιούργησε το εργαλείο.
    user_prompt = (
        "Παρακάτω σου υποβάλλω μία σύνοψη ευρημάτων από ένα AST-based εργαλείο "
        "SAST για κώδικα Python. Εντόπισε και επεξήγησε τα προβλήματα και τις ευπάθειες "
        "του κώδικα με γνώμονα την ασφάλεια-την καθαρότητά του και έπειτα πρότεινε "
        "συγκεκριμένες βελτιώσεις στον κώδικα (π.χ. ασφαλέστερες βιβλιοθήκες, patterns, "
        "επισφαλείς πρακτικές κωδικοποίησης, παραδείγματα κώδικα κλπ).\n\n"
        "=== ΣΥΝΟΨΗ ΕΥΡΗΜΑΤΩΝ ===\n"
        f"{summary_text}")
    
    try:
        # Κλήση του Chat Completions API με κατάλληλη υποβολή prompt.
        completion = openai_client.chat.completions.create(model="gpt-4.1-mini",
                                                         messages=[{
                                                             "role": "system",
                                                             "content":system_prompt},
                                                            {"role": "user",
                                                             "content": user_prompt}],
                                                             temperature=0.2)
        # Επιστρέφουμε το περιεχόμενο του πρώτου μηνύματος από το μοντέλο.
        content = completion.choices[0].message.content or "Δεν ελήφθη απάντηση από το μοντέλο του OpenAI."
        return True, content.strip()
    except Exception as exc:                            # Σε περίπτωση σφάλματος κατά την κλήση του API.
        logger.exception("Σφάλμα κατά την κλήση του OpenAI API")
        return False, f"Παρουσιάστηκε σφάλμα κατά την κλήση του OpenAI API: {exc}"
                                                                                                               
# ---------------------------------------------------------------------------
# 12. Ρυθμίσεις της σελίδας Streamlit (τίτλος καρτέλας, διάταξη σελίδας κλπ).
# ---------------------------------------------------------------------------

st.set_page_config(                                                 # Βασική ρύθμιση της σελίδας Streamlit  
    page_title="AST-based SAST Tool for Python",                    # Τίτλος καρτέλας περιηγητή.
    layout="wide"                                                   # Διάταξη σελίδας (πλήρους πλάτους).
)

# Κύριος τίτλος της εφαρμογής.
st.title("AST-based εργαλείο SAST για κώδικα Python")

# Προσθήκη περιγραφής της εφαρμογής.
st.markdown(
            """
            Αυτό το εργαλείο χρησιμοποιεί ανάλυση AST (Abstract Syntax Tree) και βιβλιοθήκες στατικής ανάλυσης (Bandit, Semgrep, Pylint, Radon) 
            με προκαθορισμένους κανόνες, καθώς και προσαρμοσμένο σύνολο κανόνων AST (SecurityVisitor) για τον εντοπισμό ευπαθειών ή επισφαλών 
            πρακτικών σε κώδικα Python.
            """
            )
# Δημιουργία διαχωριστικής γραμμής.
st.divider()

# Αρχικοποίηση state για τα ευρήματα-ChatGPT.
if "analysis_results" not in st.session_state:
    st.session_state.analysis_results = None                      # Θα κρατά όλες τις πληροφορίες (DataFrames, μετρικές κλπ) μετά την ανάλυση

if "chatgpt_advice" not in st.session_state:
    st.session_state.chatgpt_advice = ""                          # Τελευταία απάντηση-συμβουλές του ChatGPT                            

if "chatgpt_error" not in st.session_state:
    st.session_state.chatgpt_error = ""                           # Τελευταίο μήνυμα σφάλματος από το ChatGPT.

st.divider()

# Προσθήκη σύντομης οδηγία για το επόμενο βήμα του χρήστη.
st.write("Επιλέξτε ένα αρχείο με κώδικα Python που θέλετε να αναλύσετε παρακάτω:")

# -------------------------------------------------------------
# Δημιουργία κουμπιού (Button) για την επιλογή/φόρτωση αρχείου.
# -------------------------------------------------------------
uploaded_file = st.file_uploader("Επιλέξτε αρχείο με κώδικα Python (.py ή .txt)", type=["py", "txt"])

file_content: str = ""
filename: str = ""

# Προεπισκόπηση του επιλεγμένου αρχείου (Uploaded file preview field).
if uploaded_file is not None:                                              # Αν έχει ανέβει αρχείο:
    filename = uploaded_file.name                                          # Αποθήκευση του ονόματος του αρχείου.
    file_bytes: bytes = uploaded_file.read()                               # Ανάγνωση του περιεχομένου του αρχείου ως bytes.
    try:
        file_content: str = file_bytes.decode("utf-8")                     # Προσπάθεια αποκωδικοποίησης σε UTF-8.
        st.success(f"Το αρχείο '{filename}' φορτώθηκε επιτυχώς!")
    except UnicodeDecodeError:
        st.error("Σφάλμα: Αποτυχία αποκωδικοποίησης του αρχείου ως UTF-8. Παρακαλώ βεβαιωθείτε ότι το αρχείο είναι σε μορφή κειμένου UTF-8.")
        file_content = ""                                                  # Αν αποτύχει η αποκωδικοποίηση, το περιεχόμενο τίθεται σε κενό string.
    # Αν το περιεχόμενο δεν είναι κενό, εμφάνιση μηνύματος επιτυχούς φόρτωσης.
    if file_content:       
        with st.expander("Προεπισκόπηση πηγαίου κώδικα του ανεβασμένου αρχείου", expanded=False):   # Εμφάνιση περιεχομένου του αρχείου σε πλαίσιο κειμένου.
            st.code(file_content, language="python")    
        st.divider()  

    # ------------------------------------------------------
    # Επιλογή βιβλιοθήκης για ανάλυση κώδικα από τον χρήστη.
    # ------------------------------------------------------
if not file_content:                                                   # Αν δεν έχει ανέβει-διαβαστεί ο κώδικας ενημερώνεται ο χρήστης.
    st.info("Παρακαλώ ανεβάστε ένα αρχείο .py ή .txt για να ξεκινήσει η ανάλυση.")
else:
    st.subheader("Επιλογή βιβλιοθηκών ανάλυσης κώδικα:")

    col_left, col_right = st.columns(2)                                # Δημιουργία δύο στηλών για τοποθέτηση των checkboxes.

    # Δημιουργία checkboxes για επιλογή βιβλιοθηκών.
    with col_left:
        use_bandit=st.checkbox("Bandit", value=True, help="Επιλέξτε για AST-based ανάλυση με τη βιβλιοθήκη Bandit.")
        use_semgrep=st.checkbox("Semgrep", value=False, help="Επιλέξτε για pattern-based ανάλυση πάνω στο AST με τη βιβλιοθήκη Semgrep.")
        use_custom_ast=st.checkbox("Custom AST κανόνες (SecurityVisitor)", value=True, 
                               help="Επιλέξτε για εφαρμογή προσαρμοσμένων κανόνων AST εστιάζοντας σε hard-coded secrets, "
                                    "logging ευαίσθητων δεδομένων, χρήση eval/exec και subprocess με shell=True.")
    with col_right:
        use_pylint=st.checkbox("Pylint", value=False, help="Επιλέξτε για στατική ανάλυση ποιότητας κώδικα και code smells με τη βιβλιοθήκη Pylint.")
        use_radon=st.checkbox("Radon", value=False, help="Επιλέξτε για ανάλυση κυκλωματικής πολυπλοκότητας (CC) και δείκτη συντηρησιμότητας (MI) " \
                                                         "με τη βιβλιοθήκη Radon.")
        
    st.write("")

    st.divider()
      
    # ------------------------------------------------
    # Κουμπιά για έναρξη σάρωσης (Scan button) κώδικα.
    # ------------------------------------------------



    run_col_1, run_col_2 = st.columns(2)                                # Δημιουργία δύο στηλών για τοποθέτηση των κουμπιών.
    with run_col_1:
            start_scan=st.button("Έναρξη σάρωσης κώδικα", type="primary")
    with run_col_2:
            run_all = st.button("Έναρξη σάρωσης με όλες τις βιβλιοθήκες (Run All)")

    # Αν ο χρήστης πατήσει ένα εκ των δύο κουμπιών.
    if start_scan or run_all:
        # Αν το κουμπί run_all είναι True, αγνοούνται τα checkboxes και τρέχουν όλες οι βιβλιοθήκες.        
        effective_bandit = use_bandit or run_all                        # effective_* μεταβλητές καθορίζουν ποιες βιβλιοθήκες θα εκτελεστούν.
        effective_semgrep = use_semgrep or run_all
        effective_pylint = use_pylint or run_all
        effective_radon = use_radon or run_all
        effective_custom_ast = use_custom_ast or run_all
        
        # Αν δεν έχει επιλεγεί καμία βιβλιοθήκη, εμφάνιση προειδοποίησης στον χρήστη.
        if not any(
            [effective_bandit, effective_semgrep, effective_pylint, effective_radon, effective_custom_ast]
        ):
            st.warning("Παρακαλώ επιλέξτε τουλάχιστον μία βιβλιοθήκη ανάλυσης κώδικα για να συνεχίσετε.")
        else:
            # Αρχικοποίηση μεταβλητών (Dataframes) για αποθήκευση ευρημάτων ανάλυσης και μετρικών, ώστε να χρησιμοποιηθούν 
            # στο tab με το σύνολο των ευρημάτων.            
            df_bandit: pd.DataFrame | None = None            # DataFrame για αποθήκευση αποτελεσμάτων Bandit.
            df_semgrep: pd.DataFrame | None = None           # DataFrame για αποθήκευση αποτελεσμάτων Semgrep.
            df_pylint: pd.DataFrame | None = None            # DataFrame για αποθήκευση αποτελεσμάτων Pylint.
            df_radon: pd.DataFrame | None = None             # DataFrame για αποθήκευση αποτελεσμάτων Radon.
            df_custom_ast: pd.DataFrame | None = None        # DataFrame για αποθήκευση αποτελεσμάτων Custom AST αναλυτή.

            bandit_metrics: dict[str, Any] | None = None     # Μετρικές Bandit.
            pylint_score: str | None = None                  # Συνολική βαθμολογία Pylint.
            radon_mi: float | None = None                    # Δείκτης συντηρησιμότητας Radon.

            # Αποθήκευση των μηνυμάτων σφάλματος ανά βιβλιοθήκη.
            bandit_error: str | None = None
            semgrep_error: str | None = None
            pylint_error: str | None = None
            radon_error: str | None = None
            custom_ast_error: str | None = None

            # ----------------------------
            # Εκτέλεση βιβλιοθήκης Bandit.
            # ----------------------------

            if effective_bandit:
                st.subheader("Αποτελέσματα ανάλυσης με τη βιβλιοθήκη Bandit:")
                with st.spinner("Εκτέλεση ανάλυσης με τη βιβλιοθήκη Bandit.....Παρακαλώ περιμένετε"):
                    bandit_results = run_bandit_on_code(file_content)                
                
                # Έλεγχος αν η εκτέλεση ήταν επιτυχής.
                if not bandit_results["ok"]:
                    bandit_error = bandit_results.get("error") or "Άγνωστο σφάλμα"
                    st.error(f"Σφάλμα κατά την εκτέλεση του Bandit: {bandit_error}")
                    df_bandit = pd.DataFrame()
                    bandit_metrics = None
                else:
                    issues = bandit_results.get("results", [])                       # Λήψη ευρημάτων από τα αποτελέσματα.
                    bandit_metrics = bandit_results.get("metrics", {})               # Λήψη μετρικών από τα αποτελέσματα.
                    st.write(f"Συνολικά ευρήματα Bandit: {len(issues)}")
                    if bandit_metrics:
                        st.write("Μετρικές Bandit:", bandit_metrics)                           

                    if issues:
                        # Δημιουργία λίστας λεξικών για κάθε εύρημα, μορφή κατάλληλη για DataFrame.
                        rows: list[dict[str, Any]]= []
                        for issue in issues:
                            rows.append({
                                    "ID": issue.get("test_id"),
                                    "Όνομα Ελέγχου": issue.get("test_name"),
                                    "Severity": issue.get("issue_severity"),
                                    "Confidence": issue.get("issue_confidence"),
                                    "Γραμμή": issue.get("line_number"),
                                    "Αρχείο": issue.get("filename"),
                                    "Μήνυμα": issue.get("issue_text")})
                            
                        # Μετατροπή της λίστας σε pandas DataFrame για εμφάνιση.
                        df_bandit = pd.DataFrame(rows)
                            
                        # Ταξινόμηση των ευρημάτων κατά σοβαρότητα (Severity) - βεβαιότητα (Confidence).
                        if not df_bandit.empty:
                            severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
                            confidence_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
                            # Δημιουργία προσωρινών στηλών για την ταξινόμηση.
                            df_bandit["SeverityOrder"] = df_bandit["Severity"].map(severity_order).fillna(-1)
                            df_bandit["ConfidenceOrder"] = df_bandit["Confidence"].map(confidence_order).fillna(-1)
                            df_bandit = df_bandit.sort_values(by=["SeverityOrder", "ConfidenceOrder"], ascending=[False, False])
                            # Αφαίρεση βοηθητικών στηλών πριν την εμφάνιση.
                            df_bandit = df_bandit.drop(columns=["SeverityOrder", "ConfidenceOrder"])                       
                    else:
                        df_bandit = pd.DataFrame()

                if df_bandit is not None and not df_bandit.empty:
                    st.dataframe(df_bandit, use_container_width=True)
                elif df_bandit is not None:                        
                    st.info("H βιβλιοθήκη Bandit δεν εντόπισε ευπάθειες ή κενά ασφαλείας στον κώδικα του αρχείου.")
                else:
                    st.info("Τα αποτελέσματα της Bandit δεν είναι διαθέσιμα λόγω σφάλματος κατά την εκτέλεση.")
                                                                
            # -----------------------------
            # Εκτέλεση βιβλιοθήκης Semgrep.
            # -----------------------------

            if effective_semgrep:
                st.subheader("Αποτελέσματα ανάλυσης με τη βιβλιοθήκη Semgrep:") 
                with st.spinner("Εκτέλεση ανάλυσης με τη βιβλιοθήκη Semgrep.....Παρακαλώ περιμένετε"):                                       
                    semgrep_results = run_semgrep_on_code(file_content)                 # Κλήση της συνάρτησης ανάλυσης με Semgrep.
                    
                # Έλεγχος αν η εκτέλεση ήταν επιτυχής.
                if not semgrep_results["ok"]:
                    semgrep_error = semgrep_results.get("error") or "Άγνωστο σφάλμα."
                    st.error(f"Σφάλμα κατά την εκτέλεση του Semgrep: {semgrep_error}")
                    df_semgrep = pd.DataFrame()
                else:
                    sg_issues = semgrep_results.get("results", [])                      # Λήψη ευρημάτων από τα αποτελέσματα.
                    st.write(f"Συνολικά ευρήματα Semgrep: {len(sg_issues)}")

                    # Έλεγχος αν υπάρχουν ευρήματα.
                    if sg_issues:                            
                        rows: list[dict[str, Any]]= []                                  # Δημιουργία λίστας λεξικών για κάθε εύρημα.
                        for issue in sg_issues:
                            extra = issue.get("extra", {})
                            start = issue.get("start", {})
                                
                            rows.append({
                                    "Rule ID": issue.get("check_id"),
                                    "Severity": extra.get("severity"),
                                    "Γραμμή": start.get("line"),
                                    "Αρχείο": issue.get("path"),
                                    "Μήνυμα": extra.get("message")})
                            
                        # Μετατροπή της λίστας σε pandas DataFrame για εμφάνιση.
                        df_semgrep = pd.DataFrame(rows)
                            
                        # Ταξινόμηση των ευρημάτων κατά σοβαρότητα (Severity) σε φθίνουσα και Γραμμή σε αύξουσα.
                        if not df_semgrep.empty:
                            df_semgrep = df_semgrep.sort_values(by=["Severity", "Γραμμή"], ascending=[False, True])       
                    else:
                            df_semgrep = pd.DataFrame()
                            

                if df_semgrep is not None and not df_semgrep.empty:
                    st.dataframe(df_semgrep, use_container_width=True)
                elif df_semgrep is not None:                        
                    st.info("H βιβλιοθήκη Semgrep δεν εντόπισε ευπάθειες ή κενά ασφαλείας στον κώδικα του αρχείου.")
                else:
                    st.info("Τα αποτελέσματα της Semgrep δεν είναι διαθέσιμα λόγω σφάλματος κατά την εκτέλεση.")         

            # ----------------------------
            # Εκτέλεση βιβλιοθήκης Pylint.
            # ----------------------------

            if effective_pylint:
                st.subheader("Αποτελέσματα στατικής ανάλυσης με τη βιβλιοθήκη Pylint:")
                with st.spinner("Εκτέλεση ανάλυσης με τη βιβλιοθήκη Semgrep.....Παρακαλώ περιμένετε"):            
                    pylint_results = run_pylint_on_code(file_content)                    # Κλήση της συνάρτησης ανάλυσης με Pylint.
                    
                # Έλεγχος αν η εκτέλεση ήταν επιτυχής.
                if not pylint_results["ok"]:
                    pylint_error = pylint_results.get("error") or "Άγνωστο σφάλμα"
                    st.error(f"Σφάλμα κατά την εκτέλεση του Pylint: {pylint_error}")
                    df_pylint = pd.DataFrame()
                    pylint_score = None
                else:
                    pylint_messages = pylint_results.get("results", [])                  # Λήψη ευρημάτων από τα αποτελέσματα.
                    pylint_score = pylint_results.get("score")                           # Λήψη συνολικής βαθμολογίας.

                    if pylint_score:
                        st.write(f"Συνολική βαθμολογία Pylint: {pylint_score}")
                    st.write(f"Συνολικά μηνύματα Pylint: {len(pylint_messages)}")
                        

                    # Έλεγχος αν υπάρχουν ευρήματα.
                    if pylint_messages:                            
                        rows: list[dict[str, Any]]= []                                   # Δημιουργία λίστας λεξικών για κάθε μήνυμα.       
                        for msg in pylint_messages:
                            rows.append({
                                    "Τύπος": msg.get("type"),
                                    "Module": msg.get("module"),
                                    "Γραμμή": msg.get("line"),
                                    "Στήλη": msg.get("column"),
                                    "Αρχείο": msg.get("path"),
                                    "Message ID": msg.get("message-id"),
                                    "Symbol": msg.get("symbol"),
                                    "Μήνυμα": msg.get("message")})
                            
                        # Μετατροπή της λίστας σε pandas DataFrame για εμφάνιση.
                        df_pylint = pd.DataFrame(rows)
                            
                        # Ταξινόμηση των μηνυμάτων κατά τύπο (type) και γραμμή κώδικα.
                        if not df_pylint.empty:
                            df_pylint = df_pylint.sort_values(by=["Τύπος", "Γραμμή"], ascending=[True, True]) 

                    else:
                        df_pylint = pd.DataFrame()
                       
                    
                    if df_pylint is not None and not df_pylint.empty:
                        st.dataframe(df_pylint, use_container_width=True)
                    elif df_pylint is not None:                        
                        st.info("H βιβλιοθήκη Pylint δεν εντόπισε προβλήματα ποιότητας κώδικα ή code smells στο αρχείο.") 
                    else:
                        st.info("Τα αποτελέσματα της Pylint δεν είναι διαθέσιμα λόγω σφάλματος κατά την εκτέλεση.")  

            # ------------------------------------------------
            # Radon Tab - Αν έχει επιλεγεί η βιβλιοθήκη Radon.
            # ------------------------------------------------

            if effective_radon:
                st.subheader("Αποτελέσματα ανάλυσης πολυπλοκότητας με τη βιβλιοθήκη Radon:")
                with st.spinner("Εκτέλεση ανάλυσης με τη βιβλιοθήκη Radon...Παρακαλώ περιμένετε"):                                       
                    radon_results = run_radon_on_code(file_content)                              # Κλήση της συνάρτησης ανάλυσης με Radon.
                    
                # Έλεγχος αν η εκτέλεση ήταν επιτυχής.
                if not radon_results["ok"]:
                    radon_error = radon_results.get("error") or "Άγνωστο σφάλμα."
                    st.error(f"Σφάλμα κατά την εκτέλεση του Radon: {radon_error}")
                    df_radon = pd.DataFrame()
                    radon_mi = None
                else:
                        radon_issues = radon_results.get("results", [])                          # Λήψη ευρημάτων από τα αποτελέσματα.
                        radon_mi = radon_results.get("mi")                                       # Λήψη δείκτη συντηρησιμότητας (MI).
                        
                        if radon_mi is not None:
                            st.write(f"Δείκτης συντηρησιμότητας (MI): {radon_mi:.2f}")
                        st.write(f"Συνολικά μπλοκ κώδικα που αναλύθηκαν για κυκλωματική πολυπλοκότητα (CC): {len(radon_issues)}")
                        # Έλεγχος αν υπάρχουν ευρήματα.
                        if radon_issues:
                            # Μετατροπή της λίστας σε pandas DataFrame για εμφάνιση.
                            df_radon = pd.DataFrame(radon_issues)
                            
                            # Ταξινόμηση των μπλοκ κώδικα κατά κυκλωματική πολυπλοκότητα (CC).
                            if not df_radon.empty:
                                df_radon = df_radon.sort_values(by=["CC"], ascending=False)  
                        else:
                            df_radon = pd.DataFrame()
                            
                    
                if df_radon is not None and not df_radon.empty:
                    st.dataframe(df_radon, use_container_width=True)
                elif df_radon is not None:                        
                    st.info("H βιβλιοθήκη Radon δεν εντόπισε μπλοκ κώδικα με μετρήσιμη κυκλωματική πολυπλοκότητα.")
                else:
                    st.info("Τα αποτελέσματα της Radon δεν είναι διαθέσιμα λόγω σφάλματος κατά την εκτέλεση.")  
                        
            # --------------------------------------------------------------------
            # Custom AST Rules Tab - Αν έχει επιλεγεί η προσαρμοσμένη ανάλυση AST.
            # --------------------------------------------------------------------

            if effective_custom_ast:
                st.subheader("Αποτελέσματα προσαρμοσμένης ανάλυσης AST (SecurityVisitor):")
                with st.spinner("Εκτέλεση προσαρμοσμένης ανάλυσης AST...Παρακαλώ περιμένετε"):                   
                        custom_ast_results = run_custom_ast_analysis(file_content)              # Κλήση της συνάρτησης προσαρμοσμένης ανάλυσης AST.
                    # Έλεγχος αν η εκτέλεση ήταν επιτυχής.
                if not custom_ast_results["ok"]:
                    custom_ast_error = custom_ast_results.get("error") or "Άγνωστο σφάλμα."
                    st.error(f"Σφάλμα κατά την εκτέλεση της προσαρμοσμένης ανάλυσης AST: {custom_ast_error}")
                    df_custom_ast = pd.DataFrame()
                else:
                    ast_issues = custom_ast_results.get("results", [])                          # Λήψη ευρημάτων από τα αποτελέσματα.
                    st.write(f"Συνολικά ευρήματα προσαρμοσμένης ανάλυσης AST: {len(ast_issues)}")

                    # Έλεγχος αν υπάρχουν ευρήματα.
                    if ast_issues:
                        rows: list[dict[str, Any]]= []                                          # Δημιουργία λίστας λεξικών για κάθε εύρημα.
                        for issue in ast_issues:
                            rows.append({
                                    "Είδος": issue.get("Είδος"),
                                    "Όνομα": issue.get("Όνομα"),
                                    "Γραμμή": issue.get("Γραμμή"),
                                    "Λεπτομέρειες": issue.get("Λεπτομέρειες"),
                                    "Τιμή (Προεπισκόπηση)": issue.get("Τιμή (Προεπισκόπηση)", " ")})
                        # Μετατροπή της λίστας σε pandas DataFrame για εμφάνιση.
                        df_custom_ast = pd.DataFrame(rows)

                        # Ταξινόμηση των ευρημάτων κατά είδος και γραμμή κώδικα.
                        if not df_custom_ast.empty:
                            df_custom_ast = df_custom_ast.sort_values(by=["Γραμμή"], ascending=[True])
                            
                    else:
                        df_custom_ast = pd.DataFrame()

                if df_custom_ast is not None and not df_custom_ast.empty:
                    st.dataframe(df_custom_ast, use_container_width=True)
                elif df_custom_ast is not None:                        
                    st.info("Η προσαρμοσμένη ανάλυση AST (SecurityVisitor) δεν εντόπισε ευρήματα στον κώδικα του αρχείου.")
                else:
                    st.info("Τα αποτελέσματα της προσαρμοσμένης ανάλυσης AST δεν είναι διαθέσιμα λόγω σφάλματος κατά την εκτέλεση.") 

            # Αποθήκευση ευρημάτων και errors στο session_state.
            st.session_state.analysis_results = {
                "filename": filename,
                "code": file_content,
                "df_bandit": df_bandit,
                "df_semgrep": df_semgrep,
                "df_pylint": df_pylint,
                "df_radon": df_radon,
                "df_custom_ast": df_custom_ast,
                "bandit_metrics": bandit_metrics,
                "pylint_score": pylint_score,
                "radon_mi": radon_mi,
                "bandit_error": bandit_error,
                "semgrep_error": semgrep_error,
                "pylint_error": pylint_error,
                "radon_error": radon_error,
                "custom_ast_error": custom_ast_error}
            
            # Μηδενισμός τελευταίας απάντησης του ChatGPT ώστε να είναι διαθέσιμα για νέα ανάλυση.
            st.session_state.chatgpt_advice = ""
            st.session_state.chatgpt_error = ""

    # ------------------------------------------------------------------------------------------------------
    # Δημιουργία δυναμικών tabs ανάλογα με τις επιλεγμένες βιβλιοθήκες ώστε να παρουσιαστούν τα αποτελέσματα 
    # μέσω session state για κάθε βιβλιοθήκη ξεχωριστά.
    # ------------------------------------------------------------------------------------------------------

    analysis = st.session_state.analysis_results

    if analysis is not None:                      

        tabs_labels: list[str] = []
        # Δημιουργία δυναμικών tabs ανάλογα με ποια

        if analysis["df_bandit"] is not None or analysis.get("bandit_error"):
            tabs_labels.append("Bandit")
        if analysis["df_semgrep"] is not None or analysis.get("semgrep_error"):
            tabs_labels.append("Semgrep")
        if analysis["df_pylint"] is not None or analysis.get("pylint_error"):
            tabs_labels.append("Pylint")
        if analysis["df_radon"] is not None or analysis.get("radon_error"):
            tabs_labels.append("Radon")
        if analysis["df_custom_ast"] is not None or analysis.get("custom_ast_error"):
            tabs_labels.append("Custom AST Rules")
        
        # Τελευταίο tab για τη συγκεντρωτική αναφορά και το ChatGPT.
        tabs_labels.append("Σύνολο ευρημάτων ανάλυσης (Summary Report)")

        tabs = st.tabs(tabs_labels)                                          # Δημιουργία των tabs
        tab_index = 0                                                        # Δείκτης τρέχοντος tab

        # Επανεμφάνιση των DataFrames ανά βιβλιοθήκη

        if analysis["df_bandit"] is not None or analysis.get("bandit_error"):
            with tabs[tab_index]:
                st.subheader("Ευρήματα ανάλυσης με τη βιβλιοθήκη Bandit:")
                if analysis.get("bandit_error"):
                    st.info(f"Η εκτέλεση της βιβλιοθήκης Bandit απέτυχε: "
                    f"{analysis['bandit_error']}")
                if analysis["df_bandit"] is not None:
                    st.dataframe(analysis["df_bandit"], use_container_width=True)
            tab_index +=1

        if analysis["df_semgrep"] is not None or analysis.get("semgrep_error"):
            with tabs[tab_index]:
                st.subheader("Ευρήματα ανάλυσης με τη βιβλιοθήκη Semgrep:")
                if analysis.get("semgrep_error"):
                    st.info(f"Η εκτέλεση της βιβλιοθήκης Semgrep απέτυχε: "
                    f"{analysis['semgrep_error']}")
                if analysis["df_semgrep"] is not None:
                    st.dataframe(analysis["df_semgrep"], use_container_width=True)
            tab_index +=1

        if analysis["df_pylint"] is not None or analysis.get("pylint_error"):
            with tabs[tab_index]:
                st.subheader("Ευρήματα στατικής ανάλυσης με τη βιβλιοθήκη Pylint:")
                if analysis.get("pylint_error"):
                    st.info(f"Η εκτέλεση της βιβλιοθήκης Pylint απέτυχε: "
                    f"{analysis['pylint_error']}")
                if analysis["df_pylint"] is not None:
                    st.dataframe(analysis["df_pylint"], use_container_width=True)
                    if analysis["pylint_score"]:
                        st.info(f"Συνολική βαθμολογία Pylint: {analysis['pylint_score']}")
            tab_index +=1

        if analysis["df_radon"] is not None or analysis.get("radon_error"):
            with tabs[tab_index]:
                st.subheader("Ευρήματα ανάλυσης πολυπλοκότητας με τη βιβλιοθήκη Radon:")
                if analysis.get("radon_error"):
                    st.info(f"Η εκτέλεση της βιβλιοθήκης Radon απέτυχε: "
                    f"{analysis['radon_error']}")
                if analysis["df_radon"] is not None:
                    st.dataframe(analysis["df_radon"], use_container_width=True)
                    if analysis["radon_mi"] is not None:
                        st.info(f"Δείκτης συντηρησιμότητας (MI): {analysis['radon_mi']:.2f}")
            tab_index +=1

        if analysis["df_custom_ast"] is not None or analysis.get("custom_ast_error"):
            with tabs[tab_index]:
                st.subheader("Ευρήματα προσαρμοσμένης ανάλυσης με τη βιβλιοθήκη AST (SecurityVisitor):")
                if analysis.get("custom_ast_error"):
                    st.info(f"Η εκτέλεση της βιβλιοθήκης AST (SecurityVisitor) απέτυχε: "
                    f"{analysis['custom_ast_error']}")
                if analysis["df_custom_ast"] is not None:
                    st.dataframe(analysis["df_custom_ast"], use_container_width=True)
            tab_index +=1

        # ---------------------------------------------------------------------------
        # Τελευταίο tab : Σύνολο ευρημάτων ανάλυσης (Summary Report) Tab και ChatGPT.
        # ---------------------------------------------------------------------------
       
        with tabs[tab_index]:
            st.subheader("Σύνολο ευρημάτων ανάλυσης (Summary Report):")
            
            # Πραγματοποίηση ελέγχου εάν υπάρχει έστω ένα DataFrame με ευρήματα.
            has_any_findings = any(df is not None and not df.empty
                                   for df in [
                                       analysis["df_bandit"],
                                       analysis["df_semgrep"],
                                       analysis["df_pylint"],
                                       analysis["df_radon"],
                                       analysis["df_custom_ast"]])
            
            if not has_any_findings:
                st.info("Δεν υπάρχουν διαθέσιμα ευρήματα από τις επιλεγμένες βιβλιοθήκες ανάλυσης κώδικα. "
                         "Ελέγξτε ότι τουλάχιστον μία βιβλιοθήκη έχει εκτελεστεί και έχει εντοπιστεί κάποιο εύρημα.")
            else:
                # Δημιουργία της συγκεντρωτικής αναφοράς για λήψη από το χρήστη.
                summary_report = create_libr_findings_report(
                        filename=analysis["filename"],
                        code=analysis["code"],
                        df_bandit=analysis["df_bandit"],
                        df_semgrep=analysis["df_semgrep"],
                        df_pylint=analysis["df_pylint"],
                        df_radon=analysis["df_radon"],
                        df_custom_ast=analysis["df_custom_ast"],
                        bandit_metrics=analysis["bandit_metrics"],
                        pylint_score=analysis["pylint_score"],
                        radon_mi=analysis["radon_mi"])
                
                # Δημιουργία κουμπιού για λήψη της αναφοράς ως αρχείο κειμένου.
                st.download_button(
                    label="Λήψη Αναφοράς ευρημάτων ανάλυσης - κώδικα ως αρχείο κειμένου",
                    data=summary_report,
                    file_name=f"sast_summary_report_{uploaded_file.name.replace('.', '_')}.txt",
                    mime="text/plain")

                # Εμφάνιση της αναφοράς σε πλαίσιο κειμένου.
                st.text_area(
                    label="Συγκεντρωτική Αναφορά Ευρημάτων Ανάλυσης:",
                    value=summary_report,
                    height=400)
                
                st.markdown("---")

                # Δημιουργία κουμπιού για την κλήση του ChatGPT με είσοδο της σύνοψης ανάλυσης- του κώδικα
                if st.button("Λήψη προτάσεων βελτίωσης του κώδικα από το ChatGPT"):
                    summary_text = create_analysis_summary(
                        filename=analysis["filename"],
                        code=analysis["code"],
                        df_bandit=analysis["df_bandit"],
                        df_semgrep=analysis["df_semgrep"],
                        df_pylint=analysis["df_pylint"],
                        df_radon=analysis["df_radon"],
                        df_custom_ast=analysis["df_custom_ast"],
                        bandit_metrics=analysis["bandit_metrics"],
                        pylint_score=analysis["pylint_score"],
                        radon_mi=analysis["radon_mi"])

                    # Κλήση ChatGPT και αποθήκευση αποτελέσματος στο session_state.
                    ok, text = ask_chatgpt_for_sec_advice(summary_text)
                    if ok:
                        st.session_state.chatgpt_advice = text
                        st.session_state.chatgpt_error = ""
                    else:
                        st.session_state.chatgpt_advice = ""
                        st.session_state.chatgpt_error = text
                
                # Εμφάνιση απάντησης ChatGPT (εφόσον υπάρχει).
                if st.session_state.chatgpt_advice:
                    st.markdown("### Προτάσεις βελτίωσεις από το ChatGPT")
                    st.write(st.session_state.chatgpt_advice)
                elif st.session_state.chatgpt_error:
                    st.error(st.session_state.chatgpt_error)                 
    else:
        st.info("Παρακαλώ πατήστε ένα από τα δύο κουμπιά ώστε να ξεκινήσει η ανάλυση.")



                                                                                 
                        
                                

                        
                       
                              










    

   