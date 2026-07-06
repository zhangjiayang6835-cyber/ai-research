const depthLimit = require('graphql-depth-limit');
const { createComplexityLimitRule } = require('graphql-validation-complexity');

/**
 * Apply security validation rules to GraphQL server to prevent depth bypass and batching attacks.
 * @param {object} options - Configuration options.
 * @param {number} [options.maxDepth=10] - Maximum allowed query depth.
 * @param {number} [options.maxComplexity=1000] - Maximum allowed query complexity.
 * @param {number} [options.maxBatchSize=1] - Maximum number of operations in a batched query.
 * @returns {Array} Array of validation rules to pass to Apollo Server's `validationRules`.
 */
function createSecurityRules(options = {}) {
  const {
    maxDepth = 10,
    maxComplexity = 1000,
    maxBatchSize = 1,
  } = options;

  const rules = [];

  // Depth limiting
  if (maxDepth > 0) {
    rules.push(depthLimit(maxDepth));
  }

  // Complexity limiting
  if (maxComplexity > 0) {
    rules.push(createComplexityLimitRule(maxComplexity));
  }

  return rules;
}

// Middleware to enforce batch size limit
function enforceBatchLimit(maxBatchSize = 1) {
  return (req, res, next) => {
    if (Array.isArray(req.body)) {
      if (req.body.length > maxBatchSize) {
        return res.status(400).json({
          error: `Batch size exceeds maximum allowed (${maxBatchSize})`,
        });
      }
    }
    next();
  };
}

module.exports = { createSecurityRules, enforceBatchLimit };
