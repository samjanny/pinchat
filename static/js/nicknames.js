/**
 * PinChat - Deterministic Nickname Generation from UUID
 *
 * Generates human-readable nicknames (e.g., "Cosmic Fox", "Silent Panda")
 * from user UUIDs for better UX in ephemeral chat rooms.
 *
 * Features:
 * - Deterministic: Same UUID always produces same nickname
 * - Memorable: Easy to remember and reference
 * - Privacy-friendly: No real names required
 * - Collision-resistant: 10,000 unique combinations
 */

/**
 * Adjectives for nickname generation (~100 words)
 * Categories: Colors, Movements, Nature, Temperament
 */
const ADJECTIVES = [
    // Colors & Light (15)
    'Crimson', 'Azure', 'Golden', 'Silver', 'Emerald',
    'Violet', 'Amber', 'Scarlet', 'Indigo', 'Coral',
    'Obsidian', 'Pearl', 'Ivory', 'Onyx', 'Jade',

    // Movement & Action (15)
    'Dancing', 'Rolling', 'Flying', 'Jumping', 'Gliding',
    'Dashing', 'Soaring', 'Spinning', 'Racing', 'Leaping',
    'Wandering', 'Prowling', 'Floating', 'Diving', 'Charging',

    // Nature & Elements (20)
    'Cosmic', 'Stellar', 'Thunder', 'Shadow', 'Storm',
    'Frost', 'Flame', 'Crystal', 'Ocean', 'Mountain',
    'Forest', 'Desert', 'Lunar', 'Solar', 'Wind',
    'River', 'Glacier', 'Volcano', 'Aurora', 'Eclipse',

    // Temperament & Personality (25)
    'Silent', 'Bold', 'Gentle', 'Wild', 'Mystic',
    'Ancient', 'Noble', 'Clever', 'Fierce', 'Bright',
    'Serene', 'Swift', 'Brave', 'Wise', 'Cunning',
    'Loyal', 'Proud', 'Radiant', 'Eternal', 'Tranquil',
    'Valiant', 'Zealous', 'Calm', 'Daring', 'Keen',

    // Magic & Fantasy (15)
    'Arcane', 'Ethereal', 'Phantom', 'Spectral', 'Enchanted',
    'Celestial', 'Mythic', 'Legendary', 'Fabled', 'Sacred',
    'Mystic', 'Blessed', 'Cursed', 'Haunted', 'Charmed',

    // Qualities (10)
    'Hidden', 'Lost', 'Forgotten', 'Awakened', 'Frozen',
    'Burning', 'Shining', 'Glowing', 'Blazing', 'Sparkling'
];

/**
 * Nouns for nickname generation (~100 words)
 * Categories: Animals, Elements, Fantasy
 */
const NOUNS = [
    // Land Animals (20)
    'Fox', 'Wolf', 'Panda', 'Tiger', 'Bear',
    'Lion', 'Lynx', 'Panther', 'Leopard', 'Cheetah',
    'Jaguar', 'Cougar', 'Badger', 'Otter', 'Raccoon',
    'Deer', 'Elk', 'Moose', 'Bison', 'Rhino',

    // Birds (15)
    'Raven', 'Falcon', 'Eagle', 'Hawk', 'Owl',
    'Phoenix', 'Crow', 'Swan', 'Crane', 'Heron',
    'Pelican', 'Albatross', 'Condor', 'Kestrel', 'Osprey',

    // Aquatic (10)
    'Whale', 'Dolphin', 'Shark', 'Orca', 'Seal',
    'Octopus', 'Marlin', 'Barracuda', 'Manta', 'Swordfish',

    // Reptiles & Others (5)
    'Dragon', 'Cobra', 'Python', 'Viper', 'Serpent',

    // Fantasy Creatures (15)
    'Wizard', 'Knight', 'Ranger', 'Paladin', 'Sorcerer',
    'Warlock', 'Druid', 'Monk', 'Rogue', 'Bard',
    'Titan', 'Golem', 'Sprite', 'Wraith', 'Specter',

    // Elements & Nature (20)
    'Storm', 'Fire', 'River', 'Mountain', 'Forest',
    'Ocean', 'Star', 'Moon', 'Sun', 'Comet',
    'Thunder', 'Lightning', 'Blizzard', 'Tornado', 'Hurricane',
    'Volcano', 'Glacier', 'Canyon', 'Valley', 'Peak',

    // Mythological (10)
    'Atlas', 'Orion', 'Hercules', 'Perseus', 'Apollo',
    'Thor', 'Odin', 'Zeus', 'Loki', 'Freya',

    // Objects & Concepts (5)
    'Sword', 'Shield', 'Crown', 'Throne', 'Chalice'
];

/**
 * Generate deterministic nickname from UUID
 *
 * Uses first 8 hex digits of UUID to select adjective and noun.
 * Same UUID always produces same nickname.
 *
 * @param {string} uuid - UUID v4 string (e.g., "d07e20ba-00dd-4213-99a6-9bfbd1b96b87")
 * @returns {Object} Nickname object with display and short formats
 *
 * @example
 * generateNickname("d07e20ba-00dd-4213-99a6-9bfbd1b96b87")
 * // Returns: { display: "Cosmic Fox", short: "Cosmic_Fox", adjective: "Cosmic", noun: "Fox" }
 */
function generateNickname(uuid) {
    // Remove hyphens and take first 8 hex digits (32 bits)
    const hex = uuid.replace(/-/g, '').substring(0, 8);
    const num = parseInt(hex, 16);

    // Use modulo to get deterministic indices
    const adjectiveIndex = num % ADJECTIVES.length;
    const nounIndex = Math.floor(num / ADJECTIVES.length) % NOUNS.length;

    const adjective = ADJECTIVES[adjectiveIndex];
    const noun = NOUNS[nounIndex];

    return {
        display: `${adjective} ${noun}`,       // "Cosmic Fox" (for UI)
        short: `${adjective}_${noun}`,         // "Cosmic_Fox" (for logs)
        adjective: adjective,
        noun: noun,
        uuid: uuid                             // Original UUID (for reference)
    };
}

/**
 * Get short UUID representation for display (first 8 chars)
 *
 * @param {string} uuid - Full UUID string
 * @returns {string} Short UUID (e.g., "d07e20ba")
 */
function getShortUUID(uuid) {
    return uuid.replace(/-/g, '').substring(0, 8);
}

/**
 * Generate nickname with collision detection
 *
 * If nickname collision occurs in room (rare with 10,000 combinations),
 * append short UUID to make it unique.
 *
 * @param {string} uuid - User UUID
 * @param {Array<string>} existingNicknames - List of nicknames already in use
 * @returns {Object} Nickname object (possibly with UUID suffix)
 */
function generateUniqueNickname(uuid, existingNicknames = []) {
    const nickname = generateNickname(uuid);

    // Check for collision
    if (existingNicknames.includes(nickname.display)) {
        // Append short UUID to make unique
        const shortUUID = getShortUUID(uuid);
        nickname.display = `${nickname.display} (${shortUUID})`;
        nickname.short = `${nickname.short}_${shortUUID}`;
    }

    return nickname;
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { generateNickname, generateUniqueNickname, getShortUUID };
}
