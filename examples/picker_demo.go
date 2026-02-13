//go:build ignore
// +build ignore

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

// This is a demo script to showcase the fuzzy search picker functionality.
// Run this demo to see how the picker works with example AWS IAM roles.
//
// Usage:
//
//	go run examples/picker_demo.go
package main

import (
	"fmt"
	"os"

	"github.com/okta/okta-aws-cli/v2/internal/picker"
)

func main() {
	// Example AWS IAM roles with fake account IDs for demonstration
	roles := []string{
		"arn:aws:iam::123456789012:role/Admin",
		"arn:aws:iam::123456789012:role/Developer",
		"arn:aws:iam::123456789012:role/ReadOnly",
		"arn:aws:iam::123456789012:role/DevOps-Engineer",
		"arn:aws:iam::123456789012:role/Security-Analyst",
		"arn:aws:iam::987654321098:role/Production-Admin",
		"arn:aws:iam::987654321098:role/Production-Developer",
		"arn:aws:iam::987654321098:role/Production-ReadOnly",
		"arn:aws:iam::111222333444:role/Staging-Admin",
		"arn:aws:iam::111222333444:role/Staging-Developer",
		"arn:aws:iam::555666777888:role/QA-Tester",
		"arn:aws:iam::555666777888:role/QA-Lead",
		"arn:aws:iam::999000111222:role/Data-Engineer",
		"arn:aws:iam::999000111222:role/Data-Scientist",
		"arn:aws:iam::999000111222:role/ML-Engineer",
	}

	fmt.Println("=== Okta AWS CLI - Fuzzy Search Picker Demo ===")
	fmt.Println()
	fmt.Println("Tips:")
	fmt.Println("  • Type to filter roles (searches role name, not full ARN)")
	fmt.Println("  • Use ↑/↓ arrows to navigate")
	fmt.Println("  • Press Enter to select")
	fmt.Println("  • Press Esc to cancel")
	fmt.Println()

	selected, err := picker.Pick("Choose an AWS IAM Role:", roles)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Printf("✓ Selected: %s\n", selected)
}
