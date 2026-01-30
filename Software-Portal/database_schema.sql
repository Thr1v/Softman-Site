-- Software Management Portal Database Schema

-- Rooms/Locations Table
CREATE TABLE IF NOT EXISTS rooms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_name TEXT NOT NULL UNIQUE,
    building TEXT,
    floor TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Software Table
CREATE TABLE IF NOT EXISTS software (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    software_name TEXT NOT NULL,
    version TEXT NOT NULL,
    vendor TEXT,
    license_key TEXT,
    license_type TEXT, -- e.g., 'Site', 'Volume', 'Per-User'
    license_count INTEGER,
    installer_filename TEXT,
    installer_path TEXT,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Software Installations (which software is in which room)
CREATE TABLE IF NOT EXISTS installations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    software_id INTEGER NOT NULL,
    room_id INTEGER NOT NULL,
    installed_version TEXT NOT NULL,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_by TEXT,
    is_long_life BOOLEAN DEFAULT 0, -- Exception to 300-day policy
    long_life_reason TEXT,
    long_life_approved_by TEXT,
    long_life_approved_at TIMESTAMP,
    FOREIGN KEY (software_id) REFERENCES software(id) ON DELETE CASCADE,
    FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
    UNIQUE(software_id, room_id)
);

-- Update Requests Table
CREATE TABLE IF NOT EXISTS update_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    installation_id INTEGER NOT NULL,
    software_id INTEGER NOT NULL,
    room_id INTEGER NOT NULL,
    from_version TEXT,
    to_version TEXT,
    status TEXT DEFAULT 'Pending', -- 'Pending', 'Assigned', 'Approved', 'Declined', 'Completed'
    priority TEXT DEFAULT 'Normal', -- 'Low', 'Normal', 'High', 'Critical'
    requested_by TEXT,
    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    assigned_to TEXT,
    assigned_at TIMESTAMP,
    approved_by TEXT,
    approved_at TIMESTAMP,
    completed_by TEXT,
    completed_at TIMESTAMP,
    notes TEXT,
    decline_reason TEXT,
    FOREIGN KEY (installation_id) REFERENCES installations(id) ON DELETE CASCADE,
    FOREIGN KEY (software_id) REFERENCES software(id),
    FOREIGN KEY (room_id) REFERENCES rooms(id)
);

-- Update History Table (audit log)
CREATE TABLE IF NOT EXISTS update_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    installation_id INTEGER NOT NULL,
    software_id INTEGER NOT NULL,
    room_id INTEGER NOT NULL,
    from_version TEXT,
    to_version TEXT,
    updated_by TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    notes TEXT,
    FOREIGN KEY (installation_id) REFERENCES installations(id) ON DELETE CASCADE,
    FOREIGN KEY (software_id) REFERENCES software(id),
    FOREIGN KEY (room_id) REFERENCES rooms(id)
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_installations_software ON installations(software_id);
CREATE INDEX IF NOT EXISTS idx_installations_room ON installations(room_id);
CREATE INDEX IF NOT EXISTS idx_installations_updated ON installations(last_updated);
CREATE INDEX IF NOT EXISTS idx_update_requests_status ON update_requests(status);
CREATE INDEX IF NOT EXISTS idx_update_requests_software ON update_requests(software_id);
CREATE INDEX IF NOT EXISTS idx_update_requests_room ON update_requests(room_id);

-- Insert some sample data
INSERT INTO rooms (room_name, building, floor) VALUES 
    ('Lab 101', 'Main Building', '1'),
    ('Lab 102', 'Main Building', '1'),
    ('Office 201', 'Main Building', '2'),
    ('Conference Room A', 'East Wing', '1');

INSERT INTO software (software_name, version, vendor, license_type, license_count, description) VALUES 
    ('Microsoft Office', '2021', 'Microsoft', 'Volume', 500, 'Office productivity suite'),
    ('Adobe Photoshop', '2024', 'Adobe', 'Site', 100, 'Image editing software'),
    ('AutoCAD', '2024', 'Autodesk', 'Per-User', 50, 'CAD software'),
    ('Visual Studio Code', '1.85', 'Microsoft', 'Free', -1, 'Code editor');
