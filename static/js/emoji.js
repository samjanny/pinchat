/**
 * Emoji Manager - Picker and Auto-Substitution
 *
 * Features:
 * - Emoji picker with categorized emoji
 * - Automatic emoticon-to-emoji substitution (e.g., :D → 😄)
 * - Code block immunity (text inside ``` or ` is not substituted)
 * - Message rendering with code block styling
 */

class EmojiManager {
    constructor() {
        // Emoticon to emoji mapping
        // Order matters: longer patterns first to prevent partial matches
        this.emoticons = [
            // Smileys - more specific patterns first
            { pattern: ':\')', emoji: '😂' },
            { pattern: ':\'(', emoji: '😢' },
            { pattern: ':-)', emoji: '😊' },
            { pattern: ':-(', emoji: '😞' },
            { pattern: ':-D', emoji: '😄' },
            { pattern: ':-P', emoji: '😛' },
            { pattern: ':-p', emoji: '😛' },
            { pattern: ':-O', emoji: '😮' },
            { pattern: ':-o', emoji: '😮' },
            { pattern: ':-/', emoji: '😕' },
            { pattern: ':-\\', emoji: '😕' },
            { pattern: ':-|', emoji: '😐' },
            { pattern: ':-*', emoji: '😘' },
            { pattern: ';-)', emoji: '😉' },
            { pattern: 'B-)', emoji: '😎' },
            { pattern: '>:-)', emoji: '😈' },
            { pattern: '>:(', emoji: '😠' },
            { pattern: '<3', emoji: '❤️' },
            { pattern: '</3', emoji: '💔' },
            { pattern: ':)', emoji: '😊' },
            { pattern: ':(', emoji: '😞' },
            { pattern: ':D', emoji: '😄' },
            { pattern: ':P', emoji: '😛' },
            { pattern: ':p', emoji: '😛' },
            { pattern: ':O', emoji: '😮' },
            { pattern: ':o', emoji: '😮' },
            { pattern: ':/', emoji: '😕' },
            { pattern: ':\\', emoji: '😕' },
            { pattern: ':|', emoji: '😐' },
            { pattern: ':*', emoji: '😘' },
            { pattern: ';)', emoji: '😉' },
            { pattern: 'XD', emoji: '😆' },
            { pattern: 'xD', emoji: '😆' },
            { pattern: ':3', emoji: '😺' },
            { pattern: 'o_O', emoji: '😳' },
            { pattern: 'O_o', emoji: '😳' },
            { pattern: '-_-', emoji: '😑' },
            { pattern: '^_^', emoji: '😊' },
            { pattern: '>_<', emoji: '😣' },
            { pattern: 'T_T', emoji: '😭' },
            // Thumbs and gestures
            { pattern: '(y)', emoji: '👍' },
            { pattern: '(n)', emoji: '👎' },
            { pattern: '(ok)', emoji: '👌' },
            // Other
            { pattern: '(sun)', emoji: '☀️' },
            { pattern: '(moon)', emoji: '🌙' },
            { pattern: '(star)', emoji: '⭐' },
            { pattern: '(fire)', emoji: '🔥' },
            { pattern: '(check)', emoji: '✅' },
            { pattern: '(x)', emoji: '❌' },
            { pattern: '(?)', emoji: '❓' },
            { pattern: '(!)', emoji: '❗' },
        ];

        // Emoji categories for picker
        this.emojiCategories = {
            'Smileys': [
                '😊', '😄', '😃', '😁', '😆', '😅', '🤣', '😂',
                '🙂', '😉', '😌', '😍', '🥰', '😘', '😗', '😙',
                '😋', '😛', '😜', '🤪', '😝', '🤑', '🤗', '🤭',
                '🤫', '🤔', '🤐', '🤨', '😐', '😑', '😶', '😏',
                '😒', '🙄', '😬', '🤥', '😌', '😔', '😪', '🤤',
                '😴', '😷', '🤒', '🤕', '🤢', '🤮', '🤧', '🥵',
                '🥶', '🥴', '😵', '🤯', '🤠', '🥳', '🥸', '😎',
                '🤓', '🧐', '😕', '😟', '🙁', '😮', '😯', '😲',
                '😳', '🥺', '😦', '😧', '😨', '😰', '😥', '😢',
                '😭', '😱', '😖', '😣', '😞', '😓', '😩', '😫',
                '🥱', '😤', '😡', '😠', '🤬', '😈', '👿', '💀'
            ],
            'Gestures': [
                '👋', '🤚', '🖐️', '✋', '🖖', '👌', '🤌', '🤏',
                '✌️', '🤞', '🤟', '🤘', '🤙', '👈', '👉', '👆',
                '🖕', '👇', '☝️', '👍', '👎', '✊', '👊', '🤛',
                '🤜', '👏', '🙌', '👐', '🤲', '🤝', '🙏', '✍️',
                '💪', '🦾', '🦿', '🦵', '🦶', '👂', '🦻', '👃'
            ],
            'Hearts': [
                '❤️', '🧡', '💛', '💚', '💙', '💜', '🖤', '🤍',
                '🤎', '💔', '❣️', '💕', '💞', '💓', '💗', '💖',
                '💘', '💝', '💟', '♥️', '💌', '💋', '😍', '🥰'
            ],
            'Objects': [
                '🔥', '✨', '⭐', '🌟', '💫', '🎉', '🎊', '🎁',
                '🎈', '🏆', '🥇', '🥈', '🥉', '⚽', '🏀', '🏈',
                '🎮', '🎯', '🎲', '🧩', '🎭', '🎨', '🎬', '🎤',
                '🎧', '🎵', '🎶', '🔔', '📱', '💻', '⌨️', '🖥️',
                '📷', '🔦', '💡', '📚', '📖', '✏️', '📝', '📌',
                '📎', '🔑', '🔒', '🔓', '💰', '💵', '💳', '✈️',
                '🚀', '🛸', '🌈', '☀️', '🌙', '⛅', '🌧️', '❄️'
            ],
            'Symbols': [
                '✅', '❌', '❓', '❗', '💯', '🔴', '🟠', '🟡',
                '🟢', '🔵', '🟣', '⚫', '⚪', '🟤', '⬛', '⬜',
                '▶️', '⏸️', '⏹️', '⏺️', '⏭️', '⏮️', '🔀', '🔁',
                '🔂', '➕', '➖', '✖️', '➗', '♾️', '💲', '™️',
                '©️', '®️', '🔃', '🔄', '↩️', '↪️', '⬆️', '⬇️',
                '⬅️', '➡️', '↗️', '↘️', '↙️', '↖️', '↕️', '↔️'
            ],
            'Animals': [
                '🐶', '🐱', '🐭', '🐹', '🐰', '🦊', '🐻', '🐼',
                '🐨', '🐯', '🦁', '🐮', '🐷', '🐸', '🐵', '🙈',
                '🙉', '🙊', '🐔', '🐧', '🐦', '🐤', '🦆', '🦅',
                '🦉', '🦇', '🐺', '🐗', '🐴', '🦄', '🐝', '🐛',
                '🦋', '🐌', '🐞', '🐜', '🦗', '🕷️', '🦂', '🐢',
                '🐍', '🦎', '🦖', '🦕', '🐙', '🦑', '🦐', '🦀',
                '🐡', '🐠', '🐟', '🐬', '🐳', '🐋', '🦈', '🐊'
            ],
            'Food': [
                '🍎', '🍐', '🍊', '🍋', '🍌', '🍉', '🍇', '🍓',
                '🫐', '🍈', '🍒', '🍑', '🥭', '🍍', '🥥', '🥝',
                '🍅', '🥑', '🥦', '🥬', '🥒', '🌶️', '🫑', '🌽',
                '🥕', '🧄', '🧅', '🥔', '🍠', '🥐', '🥖', '🍞',
                '🥨', '🧀', '🥚', '🍳', '🥓', '🥩', '🍗', '🍖',
                '🌭', '🍔', '🍟', '🍕', '🥪', '🌮', '🌯', '🥗',
                '🍝', '🍜', '🍲', '🍛', '🍣', '🍱', '🥟', '🍤',
                '🍙', '🍚', '🍘', '🍥', '🥠', '🍡', '🧁', '🍰'
            ]
        };

        // Currently selected category
        this.selectedCategory = 'Smileys';

        // Picker visibility state
        this.isPickerOpen = false;

        // Callback when emoji is selected
        this.onEmojiSelect = null;
    }

    /**
     * Apply emoticon substitution to text, preserving code blocks
     * @param {string} text - Input text
     * @returns {string} - Text with emoticons replaced by emoji
     */
    substituteEmoticons(text) {
        if (!text) return text;

        // Strip NUL bytes from the input. The code-block extraction below uses
        // \x00CODE_BLOCK_N\x00 sentinels; if a peer-controlled plaintext
        // contains literal NUL bytes that match such a sentinel, the literal
        // String.prototype.replace below would substitute it with a code block,
        // or leave a stray sentinel in the output. Removing NUL bytes up-front
        // makes the sentinel namespace exclusive to this function.
        const codeBlocks = [];
        let processedText = text.replace(/\u0000/g, '');

        // Preserve multi-line code blocks (```)
        processedText = processedText.replace(/```[\s\S]*?```/g, (match) => {
            codeBlocks.push(match);
            return `\x00CODE_BLOCK_${codeBlocks.length - 1}\x00`;
        });

        // Preserve inline code (`)
        processedText = processedText.replace(/`[^`]+`/g, (match) => {
            codeBlocks.push(match);
            return `\x00CODE_BLOCK_${codeBlocks.length - 1}\x00`;
        });

        // Apply emoticon substitutions
        for (const { pattern, emoji } of this.emoticons) {
            // Escape special regex characters in pattern
            const escapedPattern = pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            // Match emoticon only at word boundaries or string edges
            const regex = new RegExp(`(^|\\s|[^a-zA-Z0-9])${escapedPattern}($|\\s|[^a-zA-Z0-9])`, 'g');
            processedText = processedText.replace(regex, (match, before, after) => {
                return `${before}${emoji}${after}`;
            });
        }

        // Restore code blocks.
        //
        // Audit F-3: the function form of the replacement is mandatory here.
        // With a STRING replacement, String.prototype.replace interprets the
        // `$` patterns inside it -- $&, $`, $', $$ -- and codeBlocks[i] is
        // built from peer-controlled message text. escapeHtml does not touch
        // `$`, so a message such as "`X$\'`" makes the replacement splice in
        // the portion of the subject string that FOLLOWS the match, duplicating
        // and reordering the rendered output and exposing the internal
        // \x00CODE_BLOCK_N\x00 sentinel in the UI. Not an XSS (everything
        // injected is already escaped), but it lets a sender control how their
        // own message renders in a way that diverges from the plaintext.
        // A replacer function receives the match and returns the string
        // verbatim, with no `$` interpretation.
        for (let i = 0; i < codeBlocks.length; i++) {
            processedText = processedText.replace(`\x00CODE_BLOCK_${i}\x00`, () => codeBlocks[i]);
        }

        return processedText;
    }

    /**
     * Render text with code blocks styled as HTML
     * This is used for display in message bubbles
     * @param {string} text - Input text (may contain code blocks)
     * @returns {string} - HTML with code blocks styled
     */
    renderWithCodeBlocks(text) {
        if (!text) return '';

        // Strip NUL bytes for the same reason as in substituteEmoticons:
        // the regex below uses \x00CODE_BLOCK_N\x00 as placeholder sentinels
        // that must be unique to this function's substitution pass.
        const sanitized = text.replace(/\u0000/g, '');

        // First apply emoticon substitution (preserves code blocks)
        let processedText = this.substituteEmoticons(sanitized);

        // Escape HTML entities (except in code blocks which we handle separately)
        const escapeHtml = (str) => {
            return str
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        };

        // Extract code blocks for separate processing
        const codeBlocks = [];

        // Handle multi-line code blocks (```)
        processedText = processedText.replace(/```(\w*)\n?([\s\S]*?)```/g, (match, lang, code) => {
            const escapedCode = escapeHtml(code.trim());
            const langClass = lang ? ` data-language="${escapeHtml(lang)}"` : '';
            codeBlocks.push(`<pre class="code-block"${langClass}><code>${escapedCode}</code></pre>`);
            return `\x00CODE_BLOCK_${codeBlocks.length - 1}\x00`;
        });

        // Handle inline code (`)
        processedText = processedText.replace(/`([^`]+)`/g, (match, code) => {
            const escapedCode = escapeHtml(code);
            codeBlocks.push(`<code class="inline-code">${escapedCode}</code>`);
            return `\x00CODE_BLOCK_${codeBlocks.length - 1}\x00`;
        });

        // Escape HTML in the rest of the text
        processedText = escapeHtml(processedText);

        // Restore code blocks (already have HTML).
        // Audit F-3: function form, for the same `$`-pattern reason documented
        // in substituteEmoticons above.
        for (let i = 0; i < codeBlocks.length; i++) {
            processedText = processedText.replace(`\x00CODE_BLOCK_${i}\x00`, () => codeBlocks[i]);
        }

        // Convert newlines to <br> (but not inside <pre> blocks)
        // Split by pre blocks, process text parts, rejoin
        const parts = processedText.split(/(<pre[\s\S]*?<\/pre>)/);
        processedText = parts.map((part, index) => {
            // Even indices are regular text, odd indices are pre blocks
            if (index % 2 === 0) {
                return part.replace(/\n/g, '<br>');
            }
            return part;
        }).join('');

        return processedText;
    }

    /**
     * Get emoji categories
     * @returns {Object} - Categories with emoji arrays
     */
    getCategories() {
        return this.emojiCategories;
    }

    /**
     * Get category names
     * @returns {string[]} - Array of category names
     */
    getCategoryNames() {
        return Object.keys(this.emojiCategories);
    }

    /**
     * Get emoji for a category
     * @param {string} category - Category name
     * @returns {string[]} - Array of emoji
     */
    getEmojiForCategory(category) {
        return this.emojiCategories[category] || [];
    }

    /**
     * Search emoji (simple substring match in category names)
     * @param {string} query - Search query
     * @returns {string[]} - Matching emoji
     */
    searchEmoji(query) {
        if (!query) return [];
        const lowerQuery = query.toLowerCase();
        const results = [];

        for (const [category, emojis] of Object.entries(this.emojiCategories)) {
            if (category.toLowerCase().includes(lowerQuery)) {
                results.push(...emojis);
            }
        }

        return [...new Set(results)]; // Remove duplicates
    }

    /**
     * Toggle picker visibility
     */
    togglePicker() {
        this.isPickerOpen = !this.isPickerOpen;
        return this.isPickerOpen;
    }

    /**
     * Close picker
     */
    closePicker() {
        this.isPickerOpen = false;
    }

    /**
     * Open picker
     */
    openPicker() {
        this.isPickerOpen = true;
    }

    /**
     * Select category
     * @param {string} category - Category name
     */
    selectCategory(category) {
        if (this.emojiCategories[category]) {
            this.selectedCategory = category;
        }
    }

    /**
     * Handle emoji selection
     * @param {string} emoji - Selected emoji
     */
    selectEmoji(emoji) {
        if (this.onEmojiSelect) {
            this.onEmojiSelect(emoji);
        }
        // Don't close picker - user might want to add more emoji
    }
}

// Create global instance
window.emojiManager = new EmojiManager();
