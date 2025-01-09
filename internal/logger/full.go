/*
 * Copyright (c) 2025-Present, Okta, Inc.
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

package logger

import (
	"fmt"
	"os"
)

// FullLogger logger for stderr (warn) and stdout (info) logging
type FullLogger struct {
}

func (l *FullLogger) Info(format string, a ...any) (int, error) {
	return fmt.Fprintf(os.Stdout, format, a...)
}

func (l *FullLogger) Warn(format string, a ...any) (int, error) {
	return fmt.Fprintf(os.Stderr, format, a...)
}
