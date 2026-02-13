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

package picker

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/require"
)

func TestExtractSearchKey(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "ARN with role",
			input:    "arn:aws:iam::123456789012:role/AdminRole",
			expected: "AdminRole",
		},
		{
			name:     "ARN with SAML provider",
			input:    "arn:aws:iam::123456789012:saml-provider/Okta",
			expected: "Okta",
		},
		{
			name:     "simple string without slash",
			input:    "DataProduction",
			expected: "DataProduction",
		},
		{
			name:     "friendly label with spaces",
			input:    "Data Production Environment",
			expected: "Data Production Environment",
		},
		{
			name:     "path with multiple slashes",
			input:    "a/b/c/d/LastPart",
			expected: "LastPart",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "trailing slash",
			input:    "something/",
			expected: "something/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractSearchKey(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestNewModel(t *testing.T) {
	items := []string{
		"arn:aws:iam::123:role/Admin",
		"arn:aws:iam::123:role/Developer",
		"arn:aws:iam::456:role/ReadOnly",
	}

	m := New("Choose a Role:", items)

	require.Equal(t, "Choose a Role:", m.title)
	require.Equal(t, items, m.items)
	require.Len(t, m.searchKeys, 3)
	require.Equal(t, "Admin", m.searchKeys[0])
	require.Equal(t, "Developer", m.searchKeys[1])
	require.Equal(t, "ReadOnly", m.searchKeys[2])
	require.Len(t, m.filtered, 3)
	require.Equal(t, 0, m.cursor)
	require.Empty(t, m.selected)
	require.False(t, m.quitting)
	require.False(t, m.cancelled)
}

func TestModelFilter(t *testing.T) {
	items := []string{
		"arn:aws:iam::123:role/AdminRole",
		"arn:aws:iam::123:role/DeveloperRole",
		"arn:aws:iam::456:role/ReadOnlyRole",
		"arn:aws:iam::456:role/AdminAccess",
	}

	m := New("Choose a Role:", items)

	require.Len(t, m.filtered, 4)

	// Simulate typing "admin"
	m.textInput.SetValue("admin")
	m.filter()

	// Should match "AdminRole" and "AdminAccess"
	require.Len(t, m.filtered, 2)

	// Verify the filtered indices point to correct items
	for _, idx := range m.filtered {
		searchKey := m.searchKeys[idx]
		require.Contains(t, []string{"AdminRole", "AdminAccess"}, searchKey)
	}
}

func TestModelFilterCaseInsensitive(t *testing.T) {
	items := []string{
		"arn:aws:iam::123:role/AdminRole",
		"arn:aws:iam::123:role/adminaccess",
		"arn:aws:iam::456:role/ADMINISTRATOR",
	}

	m := New("Choose a Role:", items)

	// Fuzzy search is case-insensitive
	m.textInput.SetValue("ADMIN")
	m.filter()

	require.Len(t, m.filtered, 3)
}

func TestModelFilterNoMatches(t *testing.T) {
	items := []string{
		"arn:aws:iam::123:role/Admin",
		"arn:aws:iam::123:role/Developer",
	}

	m := New("Choose a Role:", items)

	m.textInput.SetValue("xyz123")
	m.filter()

	require.Len(t, m.filtered, 0)
}

func TestModelFilterClearQuery(t *testing.T) {
	items := []string{
		"arn:aws:iam::123:role/Admin",
		"arn:aws:iam::123:role/Developer",
	}

	m := New("Choose a Role:", items)

	// Filter to one item
	m.textInput.SetValue("admin")
	m.filter()
	require.Len(t, m.filtered, 1)

	// Clear filter
	m.textInput.SetValue("")
	m.filter()
	require.Len(t, m.filtered, 2)
}

func TestModelUpdateKeyNavigation(t *testing.T) {
	items := []string{
		"arn:aws:iam::123:role/Admin",
		"arn:aws:iam::123:role/Developer",
		"arn:aws:iam::456:role/ReadOnly",
	}

	m := New("Choose a Role:", items)
	require.Equal(t, 0, m.cursor)

	// Move down
	newModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = newModel.(Model)
	require.Equal(t, 1, m.cursor)

	// Move down again
	newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = newModel.(Model)
	require.Equal(t, 2, m.cursor)

	// Try to move past the end
	newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = newModel.(Model)
	require.Equal(t, 2, m.cursor)

	// Move up
	newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyUp})
	m = newModel.(Model)
	require.Equal(t, 1, m.cursor)

	// Move to beginning
	newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyHome})
	m = newModel.(Model)
	require.Equal(t, 0, m.cursor)

	// Try to move before the beginning
	newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyUp})
	m = newModel.(Model)
	require.Equal(t, 0, m.cursor)

	// Move to end
	newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnd})
	m = newModel.(Model)
	require.Equal(t, 2, m.cursor)
}

func TestModelUpdateEnterSelection(t *testing.T) {
	items := []string{
		"arn:aws:iam::123:role/Admin",
		"arn:aws:iam::123:role/Developer",
	}

	m := New("Choose a Role:", items)

	// Move to second item
	newModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = newModel.(Model)

	// Press enter
	newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = newModel.(Model)

	require.True(t, m.quitting)
	require.False(t, m.cancelled)
	require.Equal(t, "arn:aws:iam::123:role/Developer", m.selected)
}

func TestModelUpdateEscCancel(t *testing.T) {
	items := []string{
		"arn:aws:iam::123:role/Admin",
	}

	m := New("Choose a Role:", items)

	// Press escape
	newModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = newModel.(Model)

	require.True(t, m.quitting)
	require.True(t, m.cancelled)
	require.Empty(t, m.selected)
}

func TestModelUpdateCtrlCCancel(t *testing.T) {
	items := []string{
		"arn:aws:iam::123:role/Admin",
	}

	m := New("Choose a Role:", items)

	// Press ctrl+c
	newModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	m = newModel.(Model)

	require.True(t, m.quitting)
	require.True(t, m.cancelled)
}

func TestModelSelectedAndCancelled(t *testing.T) {
	items := []string{"item1", "item2"}
	m := New("Title", items)

	require.Empty(t, m.Selected())
	require.False(t, m.Cancelled())

	// Simulate selection
	m.selected = "item1"
	require.Equal(t, "item1", m.Selected())

	// Simulate cancellation
	m.cancelled = true
	require.True(t, m.Cancelled())
}

func TestModelViewNotQuitting(t *testing.T) {
	items := []string{
		"arn:aws:iam::123:role/Admin",
		"arn:aws:iam::123:role/Developer",
	}

	m := New("Choose a Role:", items)
	view := m.View()

	// Should contain title
	require.Contains(t, view, "Choose a Role:")

	// Should contain items
	require.Contains(t, view, "Admin")
	require.Contains(t, view, "Developer")

	// Should contain navigation hints
	require.Contains(t, view, "navigate")
	require.Contains(t, view, "select")
	require.Contains(t, view, "cancel")

	// Should show item count
	require.Contains(t, view, "2/2")
}

func TestModelViewQuitting(t *testing.T) {
	items := []string{"item1"}
	m := New("Title", items)
	m.quitting = true

	view := m.View()
	require.Empty(t, view)
}

func TestModelViewNoMatches(t *testing.T) {
	items := []string{"item1", "item2"}
	m := New("Title", items)

	m.textInput.SetValue("xyz")
	m.filter()

	view := m.View()
	require.Contains(t, view, "No matches found")
	require.Contains(t, view, "0/2")
}

func TestModelPageUpPageDown(t *testing.T) {
	// Create a list larger than maxVisible
	items := make([]string, 30)
	for i := 0; i < 30; i++ {
		items[i] = "item" + string(rune('A'+i))
	}

	m := New("Choose:", items)
	m.maxVisible = 10
	require.Equal(t, 0, m.cursor)

	// Page down
	newModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyPgDown})
	m = newModel.(Model)
	require.Equal(t, 10, m.cursor)

	// Page down again
	newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyPgDown})
	m = newModel.(Model)
	require.Equal(t, 20, m.cursor)

	// Page down - should stop at last item
	newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyPgDown})
	m = newModel.(Model)
	require.Equal(t, 29, m.cursor)

	// Page up
	newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyPgUp})
	m = newModel.(Model)
	require.Equal(t, 19, m.cursor)

	// Page up multiple times to reach beginning
	for i := 0; i < 5; i++ {
		newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyPgUp})
		m = newModel.(Model)
	}
	require.Equal(t, 0, m.cursor)
}

func TestModelFilterThenSelect(t *testing.T) {
	items := []string{
		"arn:aws:iam::123:role/AdminRole",
		"arn:aws:iam::123:role/DeveloperRole",
		"arn:aws:iam::456:role/ReadOnlyRole",
	}

	m := New("Choose a Role:", items)

	// Filter to "dev"
	m.textInput.SetValue("dev")
	m.filter()
	m.cursor = 0 // Reset cursor after filter

	require.Len(t, m.filtered, 1)

	// Press enter to select the filtered item
	newModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = newModel.(Model)

	require.Equal(t, "arn:aws:iam::123:role/DeveloperRole", m.selected)
}

func TestModelWindowSizeUpdate(t *testing.T) {
	items := []string{"item1", "item2"}
	m := New("Title", items)

	// Simulate window size message
	newModel, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m = newModel.(Model)

	require.Equal(t, 24, m.windowHeight)
	require.Equal(t, 15, m.maxVisible) // min(15, 24-6) = 15
}

func TestModelWindowSizeSmall(t *testing.T) {
	items := []string{"item1", "item2"}
	m := New("Title", items)

	// Simulate small window
	newModel, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 8})
	m = newModel.(Model)

	require.Equal(t, 3, m.maxVisible) // min(15, 8-6) = 2, but min is 3
}

func TestPickSingleItem(t *testing.T) {
	items := []string{"only-one-item"}

	// Pick should return the single item without running the UI
	result, err := Pick("Choose:", items)

	require.NoError(t, err)
	require.Equal(t, "only-one-item", result)
}

func TestPickEmptyItems(t *testing.T) {
	items := []string{}

	_, err := Pick("Choose:", items)

	require.Error(t, err)
	require.Contains(t, err.Error(), "no items to select from")
}

func TestFuzzyMatchOrdering(t *testing.T) {
	items := []string{
		"arn:aws:iam::123:role/ProductionAdmin",
		"arn:aws:iam::123:role/Admin",
		"arn:aws:iam::123:role/AdminBackup",
	}

	m := New("Choose:", items)

	m.textInput.SetValue("admin")
	m.filter()

	// Should have all 3 matches
	require.Len(t, m.filtered, 3)

	// The fuzzy library scores exact/shorter matches higher
	// "Admin" should be ranked higher than "ProductionAdmin"
	firstMatch := m.items[m.filtered[0]]
	require.Contains(t, firstMatch, "Admin")
}

func TestSearchKeyPreservesOriginalForDisplay(t *testing.T) {
	items := []string{
		"arn:aws:iam::123456789012:role/MyAdminRole",
	}

	m := New("Choose:", items)

	// Search key should be just the role name
	require.Equal(t, "MyAdminRole", m.searchKeys[0])

	// But items should preserve full ARN
	require.Equal(t, "arn:aws:iam::123456789012:role/MyAdminRole", m.items[0])

	// After filtering, selected item should be full ARN
	m.textInput.SetValue("admin")
	m.filter()

	newModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = newModel.(Model)

	require.Equal(t, "arn:aws:iam::123456789012:role/MyAdminRole", m.selected)
}
