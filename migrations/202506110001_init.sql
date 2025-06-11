-- parents
CREATE TABLE parents (
    nik TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL
);

-- children
CREATE TABLE children (
    nik TEXT PRIMARY KEY,
    parent_nik TEXT NOT NULL REFERENCES parents(nik) ON DELETE CASCADE,
    name TEXT NOT NULL
);
