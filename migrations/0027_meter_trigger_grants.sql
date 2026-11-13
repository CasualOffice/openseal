-- 0027: metering trigger functions are not callable by anyone (PLAN-03 follow-up, SEC-O).
--
-- 0025 created openseal_meter_storage_trigger, openseal_meter_seats_trigger and
-- openseal_meter_workspaces_trigger as SECURITY DEFINER without revoking PostgreSQL's default
-- EXECUTE to PUBLIC, so every role, the console's included, could call them. Trigger functions
-- run from their triggers without any EXECUTE grant, so revoking it changes nothing for the
-- application and closes the door for every other role. The console catalog test
-- `the_console_role_reaches_no_public_table_or_function` checks it.
REVOKE ALL ON FUNCTION openseal_meter_storage_trigger() FROM PUBLIC;
REVOKE ALL ON FUNCTION openseal_meter_seats_trigger() FROM PUBLIC;
REVOKE ALL ON FUNCTION openseal_meter_workspaces_trigger() FROM PUBLIC;
