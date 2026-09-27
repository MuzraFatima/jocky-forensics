/**
 * JOCKY Device Utilities
 * Cleanly deduplicates target devices and management cards so duplicate
 * offline/historical records for the same endpoint are not repeatedly displayed.
 *
 * Invariants:
 * 1. Stable device_id is preserved as true identity / value.
 * 2. Display label reflects the device name and actual online/offline status.
 * 3. Currently selected device is always preserved in the returned list.
 * 4. Revoked devices are excluded from the Target dropdown.
 */

/**
 * Returns a deduplicated array of unique active endpoint devices for Target selection dropdowns.
 * Remote devices with identical hostnames are collapsed to a single entry,
 * prioritizing ONLINE status, selected device ID, and the most recent timestamp.
 *
 * @param {Array} devices - Raw list of devices from /api/agents/devices
 * @param {string|null} selectedDeviceId - Currently selected device ID
 * @returns {Array} Deduplicated list of devices
 */
export function getUniqueTargetDevices(devices, selectedDeviceId = null) {
  if (!Array.isArray(devices) || devices.length === 0) {
    return [];
  }

  // Filter out revoked devices for the Target selector (Requirement 13)
  const eligible = devices.filter((d) => !d.is_revoked && d.status !== 'revoked');

  const grouped = new Map();

  for (const dev of eligible) {
    const rawName = dev.hostname || dev.device_id || '';
    const key = rawName.trim().toLowerCase();
    if (!key) continue;

    if (!grouped.has(key)) {
      grouped.set(key, dev);
    } else {
      const current = grouped.get(key);

      // Priority 1: Keep the currently selected device if it matches this key
      if (dev.device_id === selectedDeviceId) {
        grouped.set(key, dev);
      } else if (current.device_id === selectedDeviceId) {
        // Keep current selected
      }
      // Priority 2: Prefer ONLINE device over OFFLINE device (Requirement 7)
      else if (dev.is_online && !current.is_online) {
        grouped.set(key, dev);
      } else if (!dev.is_online && current.is_online) {
        // Keep current online
      }
      // Priority 3: Prefer more recent last_seen or created_at timestamp
      else {
        const devTime = new Date(dev.last_seen || dev.created_at || 0).getTime();
        const curTime = new Date(current.last_seen || current.created_at || 0).getTime();
        if (devTime > curTime) {
          grouped.set(key, dev);
        }
      }
    }
  }

  // Sort: ONLINE devices first, then alphabetically by hostname
  return Array.from(grouped.values()).sort((a, b) => {
    if (Boolean(a.is_online) !== Boolean(b.is_online)) {
      return a.is_online ? -1 : 1;
    }
    const nameA = (a.hostname || a.device_id || '').toLowerCase();
    const nameB = (b.hostname || b.device_id || '').toLowerCase();
    return nameA.localeCompare(nameB);
  });
}

/**
 * Returns a deduplicated array of unique devices for the Endpoint Devices management grid.
 * Collapses duplicate records for the same endpoint name, prioritizing active over revoked,
 * online over offline, and most recent timestamps.
 *
 * @param {Array} devices - Raw list of devices from /api/agents/devices
 * @param {string|null} selectedDeviceId - Currently selected device ID
 * @returns {Array} Deduplicated list of devices
 */
export function getUniqueDeviceCards(devices, selectedDeviceId = null) {
  if (!Array.isArray(devices) || devices.length === 0) {
    return [];
  }

  const grouped = new Map();

  for (const dev of devices) {
    const rawName = dev.hostname || dev.device_id || '';
    const key = rawName.trim().toLowerCase();
    if (!key) continue;

    if (!grouped.has(key)) {
      grouped.set(key, dev);
    } else {
      const current = grouped.get(key);

      // Priority 1: Keep currently selected device
      if (dev.device_id === selectedDeviceId) {
        grouped.set(key, dev);
      } else if (current.device_id === selectedDeviceId) {
        // Keep current selected
      }
      // Priority 2: Non-revoked beats revoked
      else if (!dev.is_revoked && current.is_revoked) {
        grouped.set(key, dev);
      } else if (dev.is_revoked && !current.is_revoked) {
        // Keep current non-revoked
      }
      // Priority 3: ONLINE beats OFFLINE
      else if (dev.is_online && !current.is_online) {
        grouped.set(key, dev);
      } else if (!dev.is_online && current.is_online) {
        // Keep current online
      }
      // Priority 4: More recent timestamp
      else {
        const devTime = new Date(dev.last_seen || dev.created_at || 0).getTime();
        const curTime = new Date(current.last_seen || current.created_at || 0).getTime();
        if (devTime > curTime) {
          grouped.set(key, dev);
        }
      }
    }
  }

  // Sort: ONLINE first, then ACTIVE OFFLINE, then REVOKED, then alphabetically
  return Array.from(grouped.values()).sort((a, b) => {
    const aRevoked = a.is_revoked || a.status === 'revoked';
    const bRevoked = b.is_revoked || b.status === 'revoked';
    if (aRevoked !== bRevoked) {
      return aRevoked ? 1 : -1;
    }
    if (Boolean(a.is_online) !== Boolean(b.is_online)) {
      return a.is_online ? -1 : 1;
    }
    const nameA = (a.hostname || a.device_id || '').toLowerCase();
    const nameB = (b.hostname || b.device_id || '').toLowerCase();
    return nameA.localeCompare(nameB);
  });
}
