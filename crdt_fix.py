import uuid
from typing import Dict, Set, Tuple

class ORSet:
    """
    Observed-Remove Set: a CRDT that supports add and remove operations.
    Uses version vectors to resolve conflicts and prevent data corruption.
    """
    def __init__(self, node_id: str = None):
        self.node_id = node_id or str(uuid.uuid4())
        self.elements: Dict[str, Set[str]] = {}  # element -> set of tags (unique per add)
        self.removed_tags: Set[str] = set()      # all removed tags
        self.version_vector: Dict[str, int] = {}  # node_id -> counter

    def add(self, element: str) -> None:
        """Add an element with a unique tag and increment version vector."""
        tag = f"{self.node_id}:{self.version_vector.get(self.node_id, 0)}"
        self.version_vector[self.node_id] = self.version_vector.get(self.node_id, 0) + 1
        if element not in self.elements:
            self.elements[element] = set()
        self.elements[element].add(tag)

    def remove(self, element: str) -> None:
        """Remove an element by moving all its tags to removed_tags."""
        if element in self.elements:
            tags = self.elements.pop(element)
            self.removed_tags.update(tags)

    def contains(self, element: str) -> bool:
        """Check if an element is present (has at least one tag not removed)."""
        if element not in self.elements:
            return False
        # Only return True if there is at least one tag not in removed_tags
        return any(tag not in self.removed_tags for tag in self.elements[element])

    def merge(self, other: 'ORSet') -> None:
        """Merge with another ORSet, resolving conflicts using version vectors."""
        # Merge version vectors: take max
        for node_id, counter in other.version_vector.items():
            if node_id not in self.version_vector or self.version_vector[node_id] < counter:
                self.version_vector[node_id] = counter

        # Merge elements: union of tags, but only keep tags that are not in other's removed_tags
        for element, tags in other.elements.items():
            if element not in self.elements:
                self.elements[element] = set()
            for tag in tags:
                if tag not in other.removed_tags and tag not in self.removed_tags:
                    self.elements[element].add(tag)

        # Merge removed_tags: union
        self.removed_tags.update(other.removed_tags)

        # Clean up elements that are now fully removed (all tags in removed_tags)
        fully_removed = []
        for element, tags in self.elements.items():
            if all(tag in self.removed_tags for tag in tags):
                fully_removed.append(element)
        for element in fully_removed:
            del self.elements[element]

    def get_elements(self) -> Set[str]:
        """Return the set of currently present elements (values)."""
        return {elem for elem in self.elements if self.contains(elem)}

    def __repr__(self) -> str:
        return f"ORSet({self.get_elements()})"
