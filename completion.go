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
	cmd.Command("zsh").Action = func(ctx context.Context, cmd *cli.Command) error {
		if _, err := io.WriteString(cmd.Root().Writer, zshCompletionScript); err != nil {
			return fmt.Errorf("write Zsh completion: %w", err)
		}
		return nil
	}
	fish := cmd.Command("fish")
	generateFish := fish.Action
	fish.Action = func(ctx context.Context, cmd *cli.Command) error {
		if err := generateFish(ctx, cmd); err != nil {
			return err
		}
		// Fish's --force-files overrides the upstream --no-files registration
		// without replacing its command and flag completion callback.
		if _, err := io.WriteString(cmd.Root().Writer, "\ncomplete -c bbb -F\n"); err != nil {
			return fmt.Errorf("write Fish filename completion: %w", err)
		}
		return nil
	}
}

const zshCompletionScript = `#compdef bbb
compdef _bbb bbb

_bbb() {
    local -a request opts
    local i current=${(Q)PREFIX} after_separator=
    # CURRENT is one-based; PREFIX excludes the part of the word after the cursor.
    for ((i = 1; i < CURRENT; i++)); do
        request+=("${(Q)words[i]}")
        [[ $i -gt 1 && "${request[-1]}" == -- ]] && after_separator=1
    done
    if [[ -n "$after_separator" || "$current" == -* ]]; then
        request+=("$current")
    fi
    request+=(--generate-shell-completion)
    opts=("${(@f)$("${request[@]}")}") || return
    if [[ -n "${opts[1]}" ]]; then
        _describe 'values' opts
    else
        _files
    fi
}

if [[ "$funcstack[1]" == _bbb ]]; then
    _bbb
fi
`

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
    $afterSeparator = $false
    for ($i = 1; $i -lt $elements.Count; $i++) {
        $element = $elements[$i]
        if ($element.Extent.StartOffset -ge $cursorPosition) {
            break
        }
        if ($element.Extent.EndOffset -ge $cursorPosition) {
            # wordToComplete can include the part of the token after the cursor.
            $prefix = $element.Extent.Text.Substring(0, $cursorPosition - $element.Extent.StartOffset)
            break
        }
        # AST values unquote strings without expanding variables or subexpressions.
        # Redirections are not CommandElements and are deliberately not forwarded.
        if ($element -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
            $element -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) {
            $argument = $element.Value
        } else {
            $argument = $element.Extent.Text
        }
        $request += $argument
        if ($argument -eq '--') {
            $afterSeparator = $true
        }
    }
    # Preserve even an empty current argument after a completed -- separator.
    if ($afterSeparator -or $prefix.StartsWith('-')) {
        $request += $prefix
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
# Remove syntactic quotes and escapes, never expand or evaluate shell input.
__bbb_bash_unquote() {
    local word=$1 quote= char next i
    REPLY=
    for ((i = 0; i < ${#word}; i++)); do
        char=${word:i:1}
        if [[ "$quote" == "'" ]]; then
            if [[ "$char" == "'" ]]; then quote=; else REPLY+=$char; fi
        elif [[ "$char" == '\' ]]; then
            next=${word:i+1:1}
            if [[ -n "$next" && ( "$quote" != '"' || "$next" == '$' ||
                "$next" == '"' || "$next" == '\' || "$next" == $'\x60' || "$next" == $'\n' ) ]]; then
                ((i++))
                [[ "$next" == $'\n' ]] || REPLY+=$next
            else
                REPLY+=$char
            fi
        elif [[ -z "$quote" && ( "$char" == "'" || "$char" == '"' ) ]]; then
            quote=$char
        elif [[ -n "$quote" && "$char" == "$quote" ]]; then
            quote=
        else
            REPLY+=$char
        fi
    done
}

__bbb_bash_autocomplete() {
    local cur prev cword opts line token description longest=0 i candidate REPLY after_separator=
    local -a words request tokens descriptions
    COMPREPLY=()

    if declare -F _comp_initialize >/dev/null 2>&1; then
        _comp_initialize -n "=:" || return
    else
        _get_comp_words_by_ref -n "=:" cur prev words cword || return
    fi
    request=()
    for ((i = 0; i < cword; i++)); do
        __bbb_bash_unquote "${words[i]}"
        request+=("$REPLY")
        [[ $i -gt 0 && "$REPLY" == -- ]] && after_separator=1
    done
    [[ "${request[0]}" == source ]] && return
    __bbb_bash_unquote "$cur"
    cur=$REPLY
    if [[ -n "$after_separator" || "$cur" == -* ]]; then
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
