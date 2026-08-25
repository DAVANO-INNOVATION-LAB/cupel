// Package stress holds load and concurrency tests.
//
// These are not unit tests. They take minutes, allocate gigabytes, and exist to
// answer questions unit tests cannot: what happens at the scale a cluster
// actually reaches, and what happens when more than one thing runs at once.
// Run them with -tags stress.
package stress
