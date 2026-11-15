// GHSA-gcqx-w48m-w2h4 / CVE-2026-93753: a `__proto__` key must never replace the
// prototype of the object merge() returns, whatever shape the target has.
var merge = require('../')
var test = require('tape')

var poisoned = '{ "__proto__": { "isAdmin": true } }'
var nestedPoisoned = '{ "session": { "__proto__": { "isAdmin": true } } }'

function assertClean(t, object, label) {
	t.equal(Object.getPrototypeOf(object), Object.prototype, label + ': prototype is Object.prototype')
	t.equal(object.isAdmin, undefined, label + ': no inherited isAdmin')
	t.equal(Object.prototype.hasOwnProperty.call(object, '__proto__'), false, label + ': no own __proto__ key')
	t.equal({}.isAdmin, undefined, label + ': Object.prototype untouched')
}

test('null-prototype target does not let a source __proto__ through', function(t) {
	var target = Object.create(null)
	target.name = 'defaults'
	var merged = merge(target, JSON.parse(poisoned))
	assertClean(t, merged, 'null-prototype target')
	t.equal(merged.name, 'defaults', 'other target keys are kept')
	t.end()
})

test('null placeholder in the target does not let a nested source __proto__ through', function(t) {
	var merged = merge({ session: null }, JSON.parse(nestedPoisoned))
	assertClean(t, merged.session, 'null placeholder')
	t.end()
})

test('undefined placeholder in the target does not let a nested source __proto__ through', function(t) {
	var merged = merge({ session: undefined }, JSON.parse(nestedPoisoned))
	assertClean(t, merged.session, 'undefined placeholder')
	t.end()
})

test('primitive placeholder in the target does not let a nested source __proto__ through', function(t) {
	assertClean(t, merge({ session: 'none' }, JSON.parse(nestedPoisoned)).session, 'string placeholder')
	assertClean(t, merge({ session: 0 }, JSON.parse(nestedPoisoned)).session, 'number placeholder')
	t.end()
})

test('own __proto__ key on the target is not copied to the result', function(t) {
	var target = JSON.parse('{ "__proto__": { "isAdmin": true }, "name": "target" }')
	var merged = merge(target, { other: 1 })
	assertClean(t, merged, 'own __proto__ on target')
	t.equal(merged.name, 'target', 'other target keys are kept')
	t.equal(merged.other, 1, 'source keys are merged')
	t.end()
})

test('own __proto__ keys on both target and source are not merged into the result', function(t) {
	var merged = merge(JSON.parse(poisoned), JSON.parse(poisoned))
	assertClean(t, merged, 'own __proto__ on both')
	t.end()
})

test('merge.all does not let a nested __proto__ through a null placeholder', function(t) {
	var merged = merge.all([ { other: 1 }, { session: null }, JSON.parse(nestedPoisoned) ])
	assertClean(t, merged.session, 'merge.all')
	t.equal(merged.other, 1, 'earlier objects are merged')
	t.end()
})

test('__proto__ inside array elements merged into a null-prototype element is dropped', function(t) {
	var element = Object.create(null)
	var merged = merge([ element ], JSON.parse('[' + poisoned + ']'), {
		arrayMerge: function(target, source, options) {
			return target.map(function(item, index) {
				return merge(item, source[index], options)
			})
		}
	})
	assertClean(t, merged[0], 'array element')
	t.end()
})

test('ordinary and symbol keys next to __proto__ are still merged', function(t) {
	var symbolKey = Symbol('__proto__')
	var source = JSON.parse('{ "__proto__": { "isAdmin": true }, "kept": { "deep": true } }')
	source[symbolKey] = 'symbol value'
	var merged = merge({ session: null }, { session: source })
	assertClean(t, merged.session, 'mixed keys')
	t.deepEqual(merged.session.kept, { deep: true }, 'string keys are merged')
	t.equal(merged.session[symbolKey], 'symbol value', 'a symbol described as __proto__ is an ordinary key')
	t.end()
})

test('constructor and prototype keys never change the prototype of the result', function(t) {
	var source = JSON.parse('{ "session": { "constructor": { "prototype": { "isAdmin": true } }, "prototype": { "isAdmin": true } } }')
	var targets = [ { session: null }, { session: Object.create(null) }, { session: {} } ]
	targets.forEach(function(target, index) {
		var merged = merge(target, source)
		t.equal(Object.getPrototypeOf(merged.session), Object.prototype, 'target ' + index + ': prototype is Object.prototype')
		t.equal(merged.session.isAdmin, undefined, 'target ' + index + ': no inherited isAdmin')
		t.equal(Object.prototype.isAdmin, undefined, 'target ' + index + ': Object.prototype untouched')
	})
	t.end()
})
