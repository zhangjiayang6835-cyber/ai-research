function isS3BucketSecure(bucketPolicy) {
  if (!bucketPolicy || !bucketPolicy.Statement) {
    return false;
  }
  
  for (const statement of bucketPolicy.Statement) {
    if (statement.Effect === 'Allow') {
      const principal = statement.Principal;
      const isPublicPrincipal = principal === '*' || (typeof principal === 'object' && principal.AWS === '*');
      
      if (isPublicPrincipal) {
        const action = statement.Action;
        const hasDangerousAction = Array.isArray(action) 
          ? action.some(a => a === '*' || a.startsWith('s3:Get') || a.startsWith('s3:List'))
          : action === '*' || action.startsWith('s3:Get') || action.startsWith('s3:List');
          
        if (hasDangerousAction && !statement.Condition) {
          return false;
        }
      }
    }
  }
  
  return true;
}

module.exports = { isS3BucketSecure };