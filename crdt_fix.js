// Vulnerable CRDT implementation
class PNCounter {
  constructor() {
    this.P = {}; // positive increments per replica
    this.N = {}; // negative increments per replica
  }

  // Insecure merge: accepts any operation without validation
  merge(other) {
    if (typeof other !== 'object' || other === null) {
      throw new Error('Invalid merge payload');
    }
    // Vulnerability: does not check that other has P and N properties
    // An attacker could send {P: something, N: something} with malicious values
    for (let replica in other.P) {
      this.P[replica] = (this.P[replica] || 0) + other.P[replica];
    }
    for (let replica in other.N) {
      this.N[replica] = (this.N[replica] || 0) + other.N[replica];
    }
  }

  value() {
    let sum = 0;
    for (let p in this.P) sum += this.P[p];
    for (let n in this.N) sum -= this.N[n];
    return sum;
  }
}

// Fixed CRDT implementation
class PNCounterFixed {
  constructor() {
    this.P = Object.create(null); // no prototype chain
    this.N = Object.create(null);
  }

  merge(other) {
    // Type and structure validation
    if (typeof other !== 'object' || other === null) {
      throw new Error('Invalid merge payload');
    }
    if (Object.keys(other).some(k => k !== 'P' && k !== 'N')) {
      throw new Error('Unexpected properties in merge payload');
    }
    // Validate P and N are objects (or undefined)
    if (other.P !== undefined && (typeof other.P !== 'object' || other.P === null)) {
      throw new Error('Invalid P payload');
    }
    if (other.N !== undefined && (typeof other.N !== 'object' || other.N === null)) {
      throw new Error('Invalid N payload');
    }
    // Merge P
    if (other.P) {
      for (let replica in other.P) {
        if (typeof other.P[replica] !== 'number' || !Number.isFinite(other.P[replica])) {
          throw new Error('Invalid increment value');
        }
        this.P[replica] = (this.P[replica] || 0) + other.P[replica];
      }
    }
    // Merge N
    if (other.N) {
      for (let replica in other.N) {
        if (typeof other.N[replica] !== 'number' || !Number.isFinite(other.N[replica])) {
          throw new Error('Invalid decrement value');
        }
        this.N[replica] = (this.N[replica] || 0) + other.N[replica];
      }
    }
  }

  value() {
    let sum = 0;
    for (let p in this.P) sum += this.P[p];
    for (let n in this.N) sum -= this.N[n];
    return sum;
  }
}