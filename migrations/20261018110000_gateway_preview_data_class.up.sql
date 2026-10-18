-- TASK-03 contract renderer preview: content of an action evaluated at data
-- class none or synthetic has a preview.
--
-- Resolves the SPEC-QUESTION on action_content_previews in
-- 20261016181826_gateway_decisions.up.sql. data_class is the workload
-- high-water mark (COMMON WorkloadDataState, order none < synthetic <
-- internal < confidential), and the mark never goes down. none means the
-- workload has read no data, so its content carries no read data at all and
-- is no more sensitive than synthetic content. A workload that sends before
-- reading anything (M3-1 runtime) is at none, and without a preview its
-- approval contract failed closed (503). internal and confidential content
-- still has no preview, and an action without an envelope (data_class NULL)
-- still has none.
--
-- CREATE OR REPLACE VIEW keeps the column names, types and order, the owner and
-- the existing GRANT SELECT to identity_app. The view has no reloptions, before
-- or after.

CREATE OR REPLACE VIEW decisions.action_content_previews AS
SELECT DISTINCT c.content_digest,
       left(convert_from(c.content_bytes, 'UTF8'), 512) AS preview_text,
       char_length(convert_from(c.content_bytes, 'UTF8')) > 512 AS truncated
FROM decisions.action_contents c
JOIN decisions.actions a ON a.action_id = c.action_id
WHERE a.data_class IN ('none', 'synthetic');
