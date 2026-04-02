module.exports = {
	overrides: [
		{
			files: ['**/*.js', '**/*.cjs'],
			parser: require.resolve('@babel/eslint-parser'),
			parserOptions: { requireConfigFile: false, ecmaVersion: 2022, sourceType: 'module' },
			rules: {}
		}
	]
} 