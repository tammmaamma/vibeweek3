#!/bin/bash
MSG="$(date '+%Y-%m-%d %H:%M:%S') ✅ 작업 한 턴 완료"
echo "$MSG"
echo "$MSG" >> "$CLAUDE_PROJECT_DIR/.claude/worklog.txt"
exit 0

