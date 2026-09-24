//! Online garbage collection for the filesystem backend: the startup
//! consistency check (backref rebuild from the layout + candidate seeding) and
//! the periodic O(garbage) sweep driven by [`crate::gc::GcTracker`].
