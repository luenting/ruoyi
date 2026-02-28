module.exports = {
  // ... 其他配置
  rules: {
    // ... 其他规则
    'prettier/prettier': [
      'error',
      {
        // 这里的配置要和 .prettierrc.js 完全一致
        tabWidth: 4,
        semi: true,
        singleQuote: true,
        trailingComma: 'all',
        printWidth: 120,
        bracketSpacing: true,
        arrowParens: 'avoid',
        endOfLine: 'auto'
      }
    ]
  }
}