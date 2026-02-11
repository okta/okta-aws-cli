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

package backoff

import (
	"context"
	"time"
)

// Backoff is a helper to allow customized polling with github.com/cenkalti/backoff/v4
type Backoff struct {
	ctx context.Context
}

// NewBackoff Creates a new backoff
func NewBackoff(ctx context.Context) *Backoff {
	return &Backoff{
		ctx: ctx,
	}
}

// NextBackOff Satisfies github.com/cenkalti/backoff/v4 BackOff interface
func (b *Backoff) NextBackOff() time.Duration {
	return time.Second * 2
}

// Reset Satisfies github.com/cenkalti/backoff/v4 BackOff interface
func (b *Backoff) Reset() {}

// Context Satisfies github.com/cenkalti/backoff/v4 BackOff interface
func (b *Backoff) Context() context.Context {
	return b.ctx
}
