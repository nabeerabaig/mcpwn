"""Small, composable context checks for untrusted instruction text.

A keyword alone is not a finding. Each rule requires a grammatical cue and
an object in the same bounded clause (or, for approval, its adjacent clause).
"""
from __future__ import annotations

import re

_BOUNDARY = re.compile(r'(?<=[.!?])[ \t]+|\r?\n')
_LABEL = re.compile(r'^(?:description|default)\s*:\s*', re.I)
_LIST = re.compile(r'^\s*(?:[-+*]\s+|\d+[.)]\s+)?')
_ACTOR = r'(?:the\s+)?(?:ai\s+)?(?:assistant|agent|model)'
_MODAL = rf'(?:(?:you|{_ACTOR})\s+(?:must|should|shall|need to)\s+)'
_DISCLOSE = re.compile(rf'^(?:{_MODAL})?(?:print|reveal|show|disclose|expose|output)\s+(?!whether\b|how\b|why\b)', re.I)
_PRIVATE_CONTEXT = re.compile(r'\b(?:system (?:prompt|instructions?)|developer (?:messages?|instructions?)|(?:hidden|internal) configuration)\b', re.I)
_OVERRIDE = re.compile(rf'^(?:{_MODAL})?(?:disregard|ignore|override|replace|abandon)\s+', re.I)
_TASK = re.compile(r'\b(?:original task|user(?:’s|\x27s)?(?: request| instructions?)?|previous instructions)\b', re.I)
_CONDITION = re.compile(rf'^if\s+[^,;]{{0,100}}\b{_ACTOR}\b[^,;]{{0,24}},\s*', re.I)
_TARGETED = re.compile(rf'^{_ACTOR}\s+(?:must|should|shall|need to)\s+', re.I)
_AUTHORITY = re.compile(r'^(?:the\s+)?(?:security\s+)?(?:administrator|admin)\s+(?:has\s+)?(?:approved|authorized|granted)\b', re.I)
_PRIVATE_DATA = re.compile(r'\b(?:private|confidential|restricted)\s+(?:\w+\s+){0,2}(?:data|files?|records?|configuration)\b', re.I)
_NO_REVIEW = re.compile(r'\b(?:no (?:further |additional )?(?:authorization|approval|confirmation) (?:is )?(?:necessary|required)|without (?:further |additional )?(?:approval|authorization|confirmation))\b', re.I)


def _clauses(text: str):
    for segment in _BOUNDARY.split(text):
        clause = _LIST.sub('', segment, count=1).strip()
        label = _LABEL.match(clause)
        if label:
            clause = clause[label.end():].strip().strip('"\'')
        if clause and not clause.startswith(('#', '>', '`', '"', "'")):
            yield clause
        else:
            yield ''  # do not build context across an empty or quoted boundary


def signals(text: str):
    """Yield (rule, title, explanation, confidence, evidence) for distinct signals."""
    previous = ''
    seen = set()
    for clause in _clauses(text):
        rules = []
        disclosure = _DISCLOSE.match(clause)
        if disclosure and _PRIVATE_CONTEXT.search(clause, disclosure.end(), disclosure.end() + 150):
            rules.append(('CONTEXT-DISCLOSURE', 'Request for private instruction context',
                          'An imperative asks for system, developer, or hidden configuration text.', .75, clause))
        condition = _CONDITION.match(clause)
        target = clause[condition.end():] if condition else clause
        override = _OVERRIDE.match(target)
        if (condition or _TARGETED.match(clause)) and override and _TASK.search(target, override.end(), override.end() + 100):
            rules.append(('TARGETED-TASK-OVERRIDE', 'Task override aimed at an agent',
                          'An agent-targeting cue is paired with an instruction to disregard the original task or user.', .8, clause))
        for approval, followup in ((clause, ''), (previous, clause)):
            if (_AUTHORITY.match(approval) and _PRIVATE_DATA.search(approval[:200])
                    and (_NO_REVIEW.search(approval[:250]) or _NO_REVIEW.match(followup))):
                rules.append(('UNVERIFIED-AUTHORIZATION', 'Unverified approval for private data access',
                              'A claimed administrator approval is coupled with private data and a claim that no further approval is needed.',
                              .7, ' '.join(filter(None, (approval, followup)))))
                break
        previous = clause
        for row in rules:
            if row[0] not in seen:
                seen.add(row[0])
                yield row
