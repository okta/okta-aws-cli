/*
 * Copyright (c) 2026-Present, Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package picker provides a fuzzy search picker using bubbletea
package picker

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/sahilm/fuzzy"
)

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("39"))

	selectedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("170")).
			Bold(true)

	normalStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("252"))

	matchStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("39")).
			Bold(true)

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241"))

	cursorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("170"))
)

// Model represents the picker state
type Model struct {
	title        string
	items        []string
	filtered     []string
	matches      []fuzzy.Match
	cursor       int
	selected     string
	textInput    textinput.Model
	quitting     bool
	cancelled    bool
	windowHeight int
	maxVisible   int
}

// New creates a new picker model
func New(title string, items []string) Model {
	ti := textinput.New()
	ti.Placeholder = "Type to search..."
	ti.Focus()
	ti.CharLimit = 100
	ti.Width = 50
	ti.PromptStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("39"))
	ti.TextStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))

	return Model{
		title:      title,
		items:      items,
		filtered:   items,
		textInput:  ti,
		maxVisible: 15,
	}
}

// Init implements tea.Model
func (m Model) Init() tea.Cmd {
	return textinput.Blink
}

// Update implements tea.Model
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.windowHeight = msg.Height
		m.maxVisible = min(15, msg.Height-6)
		if m.maxVisible < 3 {
			m.maxVisible = 3
		}

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			m.cancelled = true
			m.quitting = true
			return m, tea.Quit

		case "enter":
			if len(m.filtered) > 0 && m.cursor < len(m.filtered) {
				m.selected = m.filtered[m.cursor]
			}
			m.quitting = true
			return m, tea.Quit

		case "up", "ctrl+p":
			if m.cursor > 0 {
				m.cursor--
			}
			return m, nil

		case "down", "ctrl+n":
			if m.cursor < len(m.filtered)-1 {
				m.cursor++
			}
			return m, nil

		case "pgup":
			m.cursor -= m.maxVisible
			if m.cursor < 0 {
				m.cursor = 0
			}
			return m, nil

		case "pgdown":
			m.cursor += m.maxVisible
			if m.cursor >= len(m.filtered) {
				m.cursor = len(m.filtered) - 1
			}
			if m.cursor < 0 {
				m.cursor = 0
			}
			return m, nil

		case "home", "ctrl+a":
			m.cursor = 0
			return m, nil

		case "end", "ctrl+e":
			if len(m.filtered) > 0 {
				m.cursor = len(m.filtered) - 1
			}
			return m, nil
		}
	}

	prevValue := m.textInput.Value()
	m.textInput, cmd = m.textInput.Update(msg)

	if m.textInput.Value() != prevValue {
		m.filter()
		m.cursor = 0
	}

	return m, cmd
}

func (m *Model) filter() {
	query := m.textInput.Value()
	if query == "" {
		m.filtered = m.items
		m.matches = nil
		return
	}

	matches := fuzzy.Find(query, m.items)
	m.matches = matches
	m.filtered = make([]string, len(matches))
	for i, match := range matches {
		m.filtered[i] = match.Str
	}
}

// View implements tea.Model
func (m Model) View() string {
	if m.quitting {
		return ""
	}

	var b strings.Builder

	b.WriteString(titleStyle.Render("? "+m.title) + "\n\n")
	b.WriteString("  " + m.textInput.View() + "\n\n")

	if len(m.filtered) == 0 {
		b.WriteString(dimStyle.Render("  No matches found\n"))
	} else {
		start := 0
		end := len(m.filtered)

		if len(m.filtered) > m.maxVisible {
			half := m.maxVisible / 2
			start = m.cursor - half
			if start < 0 {
				start = 0
			}
			end = start + m.maxVisible
			if end > len(m.filtered) {
				end = len(m.filtered)
				start = end - m.maxVisible
				if start < 0 {
					start = 0
				}
			}
		}

		if start > 0 {
			b.WriteString(dimStyle.Render(fmt.Sprintf("  ↑ %d more above\n", start)))
		}

		for i := start; i < end; i++ {
			item := m.filtered[i]
			cursor := "  "
			if i == m.cursor {
				cursor = cursorStyle.Render("> ")
			}

			displayItem := m.renderItem(i, item)
			b.WriteString(cursor + displayItem + "\n")
		}

		if end < len(m.filtered) {
			b.WriteString(dimStyle.Render(fmt.Sprintf("  ↓ %d more below\n", len(m.filtered)-end)))
		}
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.Render(fmt.Sprintf("  %d/%d", len(m.filtered), len(m.items))))
	b.WriteString(dimStyle.Render("  •  ↑/↓ navigate  •  enter select  •  esc cancel"))

	return b.String()
}

func (m Model) renderItem(index int, item string) string {
	isSelected := index == m.cursor
	hasQuery := m.textInput.Value() != ""

	if isSelected {
		if hasQuery && index < len(m.matches) {
			return m.highlightMatchesSelected(m.matches[index])
		}
		return selectedStyle.Render(item)
	}

	if hasQuery && index < len(m.matches) {
		return m.highlightMatches(m.matches[index])
	}
	return normalStyle.Render(item)
}

func (m Model) highlightMatches(match fuzzy.Match) string {
	var result strings.Builder
	matchSet := make(map[int]bool)
	for _, idx := range match.MatchedIndexes {
		matchSet[idx] = true
	}

	for i, char := range match.Str {
		if matchSet[i] {
			result.WriteString(matchStyle.Render(string(char)))
		} else {
			result.WriteString(normalStyle.Render(string(char)))
		}
	}
	return result.String()
}

func (m Model) highlightMatchesSelected(match fuzzy.Match) string {
	var result strings.Builder
	matchSet := make(map[int]bool)
	for _, idx := range match.MatchedIndexes {
		matchSet[idx] = true
	}

	for i, char := range match.Str {
		if matchSet[i] {
			result.WriteString(matchStyle.Render(string(char)))
		} else {
			result.WriteString(selectedStyle.Render(string(char)))
		}
	}
	return result.String()
}

// Selected returns the selected item
func (m Model) Selected() string {
	return m.selected
}

// Cancelled returns true if the user cancelled
func (m Model) Cancelled() bool {
	return m.cancelled
}

// Pick runs the picker and returns the selected item
func Pick(title string, items []string) (string, error) {
	if len(items) == 0 {
		return "", fmt.Errorf("no items to select from")
	}

	if len(items) == 1 {
		return items[0], nil
	}

	m := New(title, items)
	p := tea.NewProgram(m, tea.WithOutput(os.Stderr))

	finalModel, err := p.Run()
	if err != nil {
		return "", fmt.Errorf("error running picker: %w", err)
	}

	result := finalModel.(Model)
	if result.Cancelled() {
		return "", fmt.Errorf("selection cancelled")
	}

	if result.Selected() == "" {
		return "", fmt.Errorf("no item selected")
	}

	return result.Selected(), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
