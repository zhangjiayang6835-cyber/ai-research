# Second-Order SQL Injection via Stored XSS Data

## Vulnerability Summary

User comments are stored safely using parameterized queries. However, when an admin exports all comments to CSV, the export feature concatenates stored data directly into a SQL query, creating a second-order injection point.

## Attack Scenario

1. Attacker submits a comment: `'; DROP TABLE exports; --`
2. Application stores it safely via parameterized INSERT
3. Admin triggers "Export all comments to CSV"
4. Export query: `SELECT * FROM comments WHERE content LIKE '%` + stored_content + `%'`
5. The stored XSS payload is now in a different SQL context �� the injection executes

## Impact

- **Data destruction**: DROP/ALTER TABLE commands execute
- **Data exfiltration**: UNION SELECT to dump sensitive tables
- **Privilege escalation**: Stacked queries to create admin users

## Remediation

```javascript
// WRONG: String concatenation with stored data
const bad = `SELECT * FROM comments WHERE content LIKE '%${row.content}%'`;

// CORRECT: Parameterized query everywhere, including export
const safe = await pool.query(
  'SELECT * FROM comments WHERE content LIKE $1',
  [`%${row.content}%`]
);

// For bulk export, use batch parameterized query
const exportAll = await pool.query(
  'SELECT id, author, content, created_at FROM comments ORDER BY created_at DESC',
  []
);
```

Also implement input validation on stored data and output encoding when rendering.

## Checklist

- [x] All SQL queries use parameterized statements
- [x] No string concatenation for SQL queries, even with "trusted" stored data
- [x] Input validation on stored data
