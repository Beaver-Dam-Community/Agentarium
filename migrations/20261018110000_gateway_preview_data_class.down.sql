CREATE OR REPLACE VIEW decisions.action_content_previews AS
SELECT DISTINCT c.content_digest,
       left(convert_from(c.content_bytes, 'UTF8'), 512) AS preview_text,
       char_length(convert_from(c.content_bytes, 'UTF8')) > 512 AS truncated
FROM decisions.action_contents c
JOIN decisions.actions a ON a.action_id = c.action_id
WHERE a.data_class = 'synthetic';
