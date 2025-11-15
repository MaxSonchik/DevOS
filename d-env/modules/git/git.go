package git

import (
	"fmt"
	"strings"
	"time"

	"d-env/modules"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

type Module struct{}

func (m *Module) Gather() (modules.ModuleResult, error) {
	result := modules.ModuleResult{
		Data: make(map[string]interface{}),
	}

	repo, err := git.PlainOpen(".")
	if err != nil {
		return result, fmt.Errorf("not a git repository")
	}

	// Get current branch
	ref, err := repo.Head()
	if err != nil {
		return result, err
	}

	branch := ref.Name().Short()
	result.Data["branch"] = branch

	// Get worktree status
	worktree, err := repo.Worktree()
	if err != nil {
		return result, err
	}

	status, err := worktree.Status()
	if err != nil {
		return result, err
	}

	// Count changes
	modified := 0
	added := 0
	untracked := 0
	deleted := 0

	for _, fileStatus := range status {
		switch {
		case fileStatus.Staging == git.Deleted || fileStatus.Worktree == git.Deleted:
			deleted++
		case fileStatus.Staging == git.Added || fileStatus.Worktree == git.Added:
			added++
		case fileStatus.Staging == git.Modified || fileStatus.Worktree == git.Modified:
			modified++
		case fileStatus.Staging == git.Untracked || fileStatus.Worktree == git.Untracked:
			untracked++
		}
	}

	isDirty := !status.IsClean()
	result.Data["dirty"] = isDirty
	result.Data["modified"] = modified
	result.Data["added"] = added
	result.Data["deleted"] = deleted
	result.Data["untracked"] = untracked

	// Get last commit
	commitIter, err := repo.Log(&git.LogOptions{Order: git.LogOrderCommitterTime})
	if err != nil {
		return result, err
	}

	var lastCommit *object.Commit
	if lastCommit, err = commitIter.Next(); err != nil {
		return result, err
	}

	lastCommitTime := lastCommit.Author.When
	result.Data["last_commit"] = lastCommitTime.Format(time.RFC3339)

	// Get ahead/behind info (simplified)
	result.Data["ahead"] = 0
	result.Data["behind"] = 0

	// Build display
	var display strings.Builder
	display.WriteString("🔄 GIT: ")

	// Branch and sync info
	display.WriteString(fmt.Sprintf("[%s", branch))
	if ahead, ok := result.Data["ahead"].(int); ok && ahead > 0 {
		display.WriteString(fmt.Sprintf(" ↑%d", ahead))
	}
	if behind, ok := result.Data["behind"].(int); ok && behind > 0 {
		display.WriteString(fmt.Sprintf(" ↓%d", behind))
	}
	display.WriteString("]")

	// Dirty status
	if isDirty {
		changes := []string{}
		if modified > 0 {
			changes = append(changes, fmt.Sprintf("%d modified", modified))
		}
		if added > 0 {
			changes = append(changes, fmt.Sprintf("%d added", added))
		}
		if deleted > 0 {
			changes = append(changes, fmt.Sprintf("%d deleted", deleted))
		}
		if untracked > 0 {
			changes = append(changes, fmt.Sprintf("%d untracked", untracked))
		}
		display.WriteString(fmt.Sprintf(" | 🟡 Dirty (%s)", strings.Join(changes, ", ")))
	} else {
		display.WriteString(" | 🟢 Clean")
	}

	// Last commit
	display.WriteString(fmt.Sprintf(" | Last commit: %s", formatDuration(time.Since(lastCommitTime))))

	result.Display = display.String()
	return result, nil
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return "just now"
	}
	if d < time.Hour {
		return fmt.Sprintf("%.0f minutes ago", d.Minutes())
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%.0f hours ago", d.Hours())
	}
	return fmt.Sprintf("%.0f days ago", d.Hours()/24)
}
