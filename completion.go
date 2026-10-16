package main

import (
	"context"
	"fmt"
	"io"

	"github.com/urfave/cli/v3"
)

func configureShellCompletion(cmd *cli.Command) {
	cmd.Hidden = false
	// The upstream Bash and PowerShell generators evaluate command text. Keep
	// shell input as literal arguments so pressing Tab cannot execute shell syntax.
	cmd.Command("bash").Action = func(ctx context.Context, cmd *cli.Command) error {
		if _, err := io.WriteString(cmd.Root().Writer, bashCompletionScript); err != nil {
			return fmt.Errorf("write Bash completion: %w", err)
		}
		return nil
	}
	cmd.Command("pwsh").Action = func(ctx context.Context, cmd *cli.Command) error {
		if _, err := io.WriteString(cmd.Root().Writer, powerShellCompletionScript); err != nil {
			return fmt.Errorf("write PowerShell completion: %w", err)
		}
		return nil
	}
}

const powerShellCompletionScript = `# PowerShell completion for bbb.
Register-ArgumentCompleter -Native -CommandName bbb, bbb.exe -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    $elements = $commandAst.CommandElements
    if ($elements[0] -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) {
        return
    }
    $command = $elements[0].Value
    $request = @()
    $prefix = ''
    for ($i = 1; $i -lt $elements.Count; $i++) {
        $element = $elements[$i]
        if ($element.Extent.StartOffset -ge $cursorPosition) {
            break
        }
        if ($element.Extent.EndOffset -ge $cursorPosition) {
            # wordToComplete can include the part of the token after the cursor.
            $prefix = $element.Extent.Text.Substring(0, $cursorPosition - $element.Extent.StartOffset)
            if ($prefix.StartsWith('-')) {
                $request += $prefix
            }
            break
        }
        # AST values unquote strings without expanding variables or subexpressions.
        # Redirections are not CommandElements and are deliberately not forwarded.
        if ($element -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
            $element -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) {
            $request += $element.Value
        } else {
            $request += $element.Extent.Text
        }
    }
    $request += '--generate-shell-completion'
    & $command @request | ForEach-Object {
        $parts = $_.Split(':', 2)
        $completion = $parts[0].Trim()
        if ($completion -and $completion.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            $description = $completion
            if ($parts.Count -eq 2 -and $parts[1].Trim()) {
                $description = $parts[1].Trim()
            }
            [System.Management.Automation.CompletionResult]::new($completion, $completion, 'ParameterValue', $description)
        }
    }
}
`

const bashCompletionScript = `# Bash completion for bbb (requires bash-completion).
__bbb_bash_autocomplete() {
    local cur prev cword opts line token description longest=0 i candidate
    local -a words request tokens descriptions
    COMPREPLY=()

    if declare -F _comp_initialize >/dev/null 2>&1; then
        _comp_initialize -n "=:" || return
    else
        _get_comp_words_by_ref -n "=:" cur prev words cword || return
    fi
    [[ "${words[0]}" == source ]] && return

    request=("${words[@]:0:cword}")
    if [[ "$cur" == -* ]]; then
        request+=("$cur")
    fi
    request+=(--generate-shell-completion)
    opts=$("${request[@]}") || return

    tokens=()
    descriptions=()
    while IFS= read -r line; do
        token="${line%%:*}"
        [[ -n "$token" && "$token" == "$cur"* ]] || continue
        description=""
        if [[ "$line" == *:* ]]; then
            description="${line#*:}"
        fi
        tokens+=("$token")
        descriptions+=("$description")
        if (( ${#token} > longest )); then
            longest=${#token}
        fi
    done <<< "$opts"

    for i in "${!tokens[@]}"; do
        candidate="${tokens[i]}"
        if [[ "${COMP_TYPE:-}" == 63 && -n "${descriptions[i]}" ]]; then
            printf -v candidate '%-*s  -- %s' "$longest" "$candidate" "${descriptions[i]}"
        fi
        COMPREPLY+=("$candidate")
    done
    return 0
}

complete -o bashdefault -o default -F __bbb_bash_autocomplete bbb
`
