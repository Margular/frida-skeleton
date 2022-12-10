"""
attrdict contains several mapping objects that allow access to their
keys as attributes.
"""
from .mapping import AttrMap
from .dictionary import AttrDict
from .default import AttrDefault


__all__ = ['AttrMap', 'AttrDict', 'AttrDefault']
