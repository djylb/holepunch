// Package conf has a variable written by another package.
package conf

// Limit is written by coord.
var Limit = 3 // want "noglobalstate"
