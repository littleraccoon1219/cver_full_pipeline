-- CVER Trusted Knowledge Base formal research schema
-- Schema version: 1.0.0
-- Generated from cver/knowledge/schema.py
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS kb_schema_migrations(
        version TEXT PRIMARY KEY,
        applied_at TEXT NOT NULL,
        checksum TEXT,
        notes TEXT
    );

CREATE TABLE IF NOT EXISTS kb_actors(
        actor_id TEXT PRIMARY KEY,
        actor_type TEXT NOT NULL CHECK(actor_type IN ('human','system','model','organization')),
        display_name TEXT NOT NULL,
        affiliation TEXT,
        contact TEXT,
        public_key TEXT,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

CREATE TABLE IF NOT EXISTS kb_ingestion_runs(
        ingestion_run_id TEXT PRIMARY KEY,
        collector_name TEXT NOT NULL,
        collector_version TEXT NOT NULL,
        source_family TEXT NOT NULL,
        query_json TEXT NOT NULL,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        status TEXT NOT NULL CHECK(status IN ('running','completed','partial','failed','cancelled')),
        requested_by TEXT,
        stats_json TEXT NOT NULL DEFAULT '{}',
        error_json TEXT NOT NULL DEFAULT '{}',
        FOREIGN KEY(requested_by) REFERENCES kb_actors(actor_id)
    );

CREATE TABLE IF NOT EXISTS kb_ingestion_items(
        ingestion_item_id TEXT PRIMARY KEY,
        ingestion_run_id TEXT NOT NULL,
        external_key TEXT,
        source_id TEXT,
        record_id TEXT,
        status TEXT NOT NULL CHECK(status IN ('discovered','downloaded','normalized','imported','skipped','failed')),
        reason TEXT,
        raw_hash TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(ingestion_run_id, external_key),
        FOREIGN KEY(ingestion_run_id) REFERENCES kb_ingestion_runs(ingestion_run_id) ON DELETE CASCADE
    );

CREATE TABLE IF NOT EXISTS kb_audit_events(
        audit_event_id INTEGER PRIMARY KEY AUTOINCREMENT,
        occurred_at TEXT NOT NULL,
        actor_id TEXT,
        action TEXT NOT NULL,
        object_type TEXT NOT NULL,
        object_id TEXT NOT NULL,
        before_hash TEXT,
        after_hash TEXT,
        reason TEXT,
        correlation_id TEXT,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        FOREIGN KEY(actor_id) REFERENCES kb_actors(actor_id)
    );

CREATE TABLE IF NOT EXISTS kb_taxonomy_versions(
        taxonomy_version TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        status TEXT NOT NULL CHECK(status IN ('draft','active','deprecated')),
        content_hash TEXT NOT NULL,
        released_at TEXT,
        created_by TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(created_by) REFERENCES kb_actors(actor_id)
    );

CREATE TABLE IF NOT EXISTS kb_taxonomy_nodes(
        taxonomy_node_id TEXT PRIMARY KEY,
        taxonomy_version TEXT NOT NULL,
        taxonomy_name TEXT NOT NULL,
        code TEXT NOT NULL,
        node_type TEXT NOT NULL,
        parent_node_id TEXT,
        level INTEGER NOT NULL CHECK(level >= 0),
        name_en TEXT NOT NULL,
        name_zh TEXT,
        definition_en TEXT,
        definition_zh TEXT,
        inclusion_json TEXT NOT NULL DEFAULT '[]',
        exclusion_json TEXT NOT NULL DEFAULT '[]',
        status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('draft','active','deprecated')),
        sort_order INTEGER NOT NULL DEFAULT 0,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        UNIQUE(taxonomy_version, taxonomy_name, code),
        FOREIGN KEY(taxonomy_version) REFERENCES kb_taxonomy_versions(taxonomy_version),
        FOREIGN KEY(parent_node_id) REFERENCES kb_taxonomy_nodes(taxonomy_node_id)
    );

CREATE TABLE IF NOT EXISTS kb_taxonomy_edges(
        taxonomy_edge_id TEXT PRIMARY KEY,
        taxonomy_version TEXT NOT NULL,
        source_node_id TEXT NOT NULL,
        target_node_id TEXT NOT NULL,
        relation_type TEXT NOT NULL,
        rationale TEXT,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        UNIQUE(taxonomy_version, source_node_id, target_node_id, relation_type),
        FOREIGN KEY(taxonomy_version) REFERENCES kb_taxonomy_versions(taxonomy_version),
        FOREIGN KEY(source_node_id) REFERENCES kb_taxonomy_nodes(taxonomy_node_id),
        FOREIGN KEY(target_node_id) REFERENCES kb_taxonomy_nodes(taxonomy_node_id)
    );

CREATE TABLE IF NOT EXISTS kb_records(
        record_id TEXT PRIMARY KEY,
        record_type TEXT NOT NULL CHECK(record_type IN ('vulnerability','misconfiguration','attack_pattern','supply_chain_incident')),
        external_id TEXT,
        canonical_key TEXT,
        title_en TEXT NOT NULL,
        title_zh TEXT,
        status TEXT NOT NULL CHECK(status IN ('candidate','normalized','annotated','verified','gold','deprecated','conflicted')),
        root_cause_l1 TEXT,
        root_cause_l2 TEXT,
        root_cause_confidence TEXT,
        summary_en TEXT,
        summary_zh TEXT,
        attributes_json TEXT NOT NULL,
        content_hash TEXT NOT NULL,
        schema_version TEXT NOT NULL DEFAULT '1.0.0',
        taxonomy_version TEXT,
        review_status TEXT NOT NULL DEFAULT 'unreviewed' CHECK(review_status IN ('unreviewed','in_review','approved','rejected','needs_revision')),
        generated_by_model INTEGER NOT NULL DEFAULT 0 CHECK(generated_by_model IN (0,1)),
        deprecated_reason TEXT,
        deleted_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(taxonomy_version) REFERENCES kb_taxonomy_versions(taxonomy_version)
    );

CREATE UNIQUE INDEX IF NOT EXISTS idx_kb_records_external ON kb_records(record_type, external_id) WHERE external_id IS NOT NULL AND external_id <> '';

CREATE UNIQUE INDEX IF NOT EXISTS idx_kb_records_canonical ON kb_records(canonical_key) WHERE canonical_key IS NOT NULL AND canonical_key <> '';

CREATE INDEX IF NOT EXISTS idx_kb_records_taxonomy ON kb_records(root_cause_l1, root_cause_l2);

CREATE INDEX IF NOT EXISTS idx_kb_records_status_type ON kb_records(status, record_type);

CREATE TABLE IF NOT EXISTS kb_record_identifiers(
        identifier_id TEXT PRIMARY KEY,
        record_id TEXT NOT NULL,
        scheme TEXT NOT NULL,
        identifier_value TEXT NOT NULL,
        is_primary INTEGER NOT NULL DEFAULT 0 CHECK(is_primary IN (0,1)),
        source_id TEXT,
        valid_from TEXT,
        valid_to TEXT,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        UNIQUE(scheme, identifier_value),
        FOREIGN KEY(record_id) REFERENCES kb_records(record_id) ON DELETE CASCADE
    );

CREATE TABLE IF NOT EXISTS kb_record_revisions(
        revision_id INTEGER PRIMARY KEY AUTOINCREMENT,
        record_id TEXT NOT NULL,
        revision_no INTEGER NOT NULL,
        content_hash TEXT NOT NULL,
        snapshot_json TEXT NOT NULL,
        changed_by TEXT NOT NULL,
        change_reason TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(record_id, revision_no),
        FOREIGN KEY(record_id) REFERENCES kb_records(record_id)
    );

CREATE TABLE IF NOT EXISTS kb_record_relations(
        relation_id TEXT PRIMARY KEY,
        source_record_id TEXT NOT NULL,
        target_record_id TEXT NOT NULL,
        relation_type TEXT NOT NULL,
        relation_role TEXT,
        confidence_status TEXT NOT NULL DEFAULT 'unknown',
        verification_status TEXT NOT NULL DEFAULT 'unknown',
        assertion_id TEXT,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        created_by TEXT,
        created_at TEXT NOT NULL,
        UNIQUE(source_record_id, target_record_id, relation_type, relation_role),
        CHECK(source_record_id <> target_record_id),
        FOREIGN KEY(source_record_id) REFERENCES kb_records(record_id),
        FOREIGN KEY(target_record_id) REFERENCES kb_records(record_id),
        FOREIGN KEY(created_by) REFERENCES kb_actors(actor_id)
    );

CREATE TABLE IF NOT EXISTS kb_products(
        product_id TEXT PRIMARY KEY,
        vendor TEXT,
        product_name TEXT NOT NULL,
        ecosystem TEXT,
        purl TEXT,
        cpe TEXT,
        homepage_url TEXT,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        UNIQUE(vendor, product_name, ecosystem)
    );

CREATE TABLE IF NOT EXISTS kb_components(
        component_id TEXT PRIMARY KEY,
        product_id TEXT,
        component_name TEXT NOT NULL,
        component_type TEXT NOT NULL,
        repository_url TEXT,
        package_name TEXT,
        language TEXT,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        UNIQUE(product_id, component_name),
        FOREIGN KEY(product_id) REFERENCES kb_products(product_id)
    );

CREATE TABLE IF NOT EXISTS kb_record_components(
        record_component_id TEXT PRIMARY KEY,
        record_id TEXT NOT NULL,
        component_id TEXT NOT NULL,
        relationship_type TEXT NOT NULL CHECK(relationship_type IN ('affected','fixed_in','introduced_by','exploited_through','mitigated_by','context')),
        is_primary INTEGER NOT NULL DEFAULT 0 CHECK(is_primary IN (0,1)),
        assertion_id TEXT,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        UNIQUE(record_id, component_id, relationship_type),
        FOREIGN KEY(record_id) REFERENCES kb_records(record_id) ON DELETE CASCADE,
        FOREIGN KEY(component_id) REFERENCES kb_components(component_id)
    );

CREATE TABLE IF NOT EXISTS kb_version_ranges(
        version_range_id TEXT PRIMARY KEY,
        record_component_id TEXT NOT NULL,
        range_type TEXT NOT NULL CHECK(range_type IN ('affected','unaffected','fixed','introduced','unknown')),
        version_scheme TEXT NOT NULL,
        introduced TEXT,
        fixed TEXT,
        last_affected TEXT,
        first_unaffected TEXT,
        raw_expression TEXT,
        status TEXT NOT NULL DEFAULT 'candidate' CHECK(status IN ('candidate','verified','conflicted','deprecated')),
        assertion_id TEXT,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        FOREIGN KEY(record_component_id) REFERENCES kb_record_components(record_component_id) ON DELETE CASCADE
    );

CREATE TABLE IF NOT EXISTS kb_record_taxonomy_assignments(
        assignment_id TEXT PRIMARY KEY,
        record_id TEXT NOT NULL,
        taxonomy_node_id TEXT NOT NULL,
        assignment_role TEXT NOT NULL CHECK(assignment_role IN ('primary','secondary','context','impact','entry_point','boundary','attack_layer')),
        confidence_status TEXT NOT NULL DEFAULT 'unknown',
        verification_status TEXT NOT NULL DEFAULT 'unknown',
        assertion_id TEXT,
        assigned_by TEXT,
        assigned_at TEXT NOT NULL,
        rationale TEXT,
        UNIQUE(record_id, taxonomy_node_id, assignment_role),
        FOREIGN KEY(record_id) REFERENCES kb_records(record_id) ON DELETE CASCADE,
        FOREIGN KEY(taxonomy_node_id) REFERENCES kb_taxonomy_nodes(taxonomy_node_id),
        FOREIGN KEY(assigned_by) REFERENCES kb_actors(actor_id)
    );

CREATE TABLE IF NOT EXISTS kb_external_taxonomy_mappings(
        mapping_id TEXT PRIMARY KEY,
        taxonomy_node_id TEXT NOT NULL,
        external_system TEXT NOT NULL,
        external_code TEXT NOT NULL,
        relation_type TEXT NOT NULL CHECK(relation_type IN ('exact','narrower','broader','related','candidate')),
        confidence_status TEXT NOT NULL DEFAULT 'unknown',
        evidence_id TEXT,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        UNIQUE(taxonomy_node_id, external_system, external_code, relation_type),
        FOREIGN KEY(taxonomy_node_id) REFERENCES kb_taxonomy_nodes(taxonomy_node_id)
    );

CREATE TABLE IF NOT EXISTS kb_sources(
        source_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        source_type TEXT NOT NULL,
        authority_level TEXT NOT NULL CHECK(authority_level IN ('E0','E1','E2','E3','E4')),
        url TEXT,
        publisher TEXT,
        license_name TEXT,
        retrieved_at TEXT,
        metadata_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

CREATE TABLE IF NOT EXISTS kb_source_snapshots(
        snapshot_id TEXT PRIMARY KEY,
        source_id TEXT NOT NULL,
        content_hash TEXT NOT NULL,
        storage_path TEXT NOT NULL,
        media_type TEXT,
        captured_at TEXT NOT NULL,
        metadata_json TEXT NOT NULL,
        UNIQUE(source_id, content_hash),
        FOREIGN KEY(source_id) REFERENCES kb_sources(source_id)
    );

CREATE TABLE IF NOT EXISTS kb_evidence_fragments(
        evidence_id TEXT PRIMARY KEY,
        source_id TEXT NOT NULL,
        snapshot_id TEXT NOT NULL,
        locator TEXT NOT NULL,
        excerpt TEXT NOT NULL,
        evidence_level TEXT NOT NULL CHECK(evidence_level IN ('E0','E1','E2','E3','E4')),
        content_hash TEXT NOT NULL,
        language TEXT NOT NULL,
        fragment_type TEXT NOT NULL DEFAULT 'text',
        start_offset INTEGER,
        end_offset INTEGER,
        metadata_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(snapshot_id, locator, content_hash),
        FOREIGN KEY(source_id) REFERENCES kb_sources(source_id),
        FOREIGN KEY(snapshot_id) REFERENCES kb_source_snapshots(snapshot_id)
    );

CREATE TABLE IF NOT EXISTS kb_assertions(
        assertion_id TEXT PRIMARY KEY,
        record_id TEXT NOT NULL,
        predicate TEXT NOT NULL,
        object_json TEXT NOT NULL,
        assertion_type TEXT NOT NULL DEFAULT 'fact' CHECK(assertion_type IN ('fact','classification','condition','impact','mitigation','relationship','measurement')),
        verification_status TEXT NOT NULL CHECK(verification_status IN ('verified','strong','moderate','inferred','unknown','rejected','conflicted')),
        asserted_by TEXT NOT NULL,
        generated_by_model INTEGER NOT NULL DEFAULT 0 CHECK(generated_by_model IN (0,1)),
        valid_from TEXT,
        valid_to TEXT,
        supersedes_assertion_id TEXT,
        content_hash TEXT,
        notes TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(record_id) REFERENCES kb_records(record_id),
        FOREIGN KEY(supersedes_assertion_id) REFERENCES kb_assertions(assertion_id)
    );

CREATE INDEX IF NOT EXISTS idx_kb_assertions_record_predicate ON kb_assertions(record_id, predicate);

CREATE TABLE IF NOT EXISTS kb_assertion_revisions(
        assertion_revision_id INTEGER PRIMARY KEY AUTOINCREMENT,
        assertion_id TEXT NOT NULL,
        revision_no INTEGER NOT NULL,
        content_hash TEXT NOT NULL,
        snapshot_json TEXT NOT NULL,
        changed_by TEXT NOT NULL,
        change_reason TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(assertion_id, revision_no),
        FOREIGN KEY(assertion_id) REFERENCES kb_assertions(assertion_id)
    );

CREATE TABLE IF NOT EXISTS kb_assertion_evidence(
        assertion_id TEXT NOT NULL,
        evidence_id TEXT NOT NULL,
        support_type TEXT NOT NULL DEFAULT 'supports' CHECK(support_type IN ('supports','contradicts','qualifies','context')),
        strength REAL CHECK(strength IS NULL OR (strength >= 0 AND strength <= 1)),
        notes TEXT,
        PRIMARY KEY(assertion_id, evidence_id),
        FOREIGN KEY(assertion_id) REFERENCES kb_assertions(assertion_id) ON DELETE CASCADE,
        FOREIGN KEY(evidence_id) REFERENCES kb_evidence_fragments(evidence_id)
    );

CREATE TABLE IF NOT EXISTS kb_assertion_conflicts(
        conflict_id TEXT PRIMARY KEY,
        record_id TEXT NOT NULL,
        predicate TEXT NOT NULL,
        conflict_type TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'medium' CHECK(severity IN ('low','medium','high','critical')),
        status TEXT NOT NULL CHECK(status IN ('open','under_review','resolved','accepted_uncertainty','dismissed')),
        summary TEXT NOT NULL,
        detected_by TEXT,
        detected_at TEXT NOT NULL,
        resolved_at TEXT,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        FOREIGN KEY(record_id) REFERENCES kb_records(record_id),
        FOREIGN KEY(detected_by) REFERENCES kb_actors(actor_id)
    );

CREATE TABLE IF NOT EXISTS kb_conflict_assertions(
        conflict_id TEXT NOT NULL,
        assertion_id TEXT NOT NULL,
        conflict_role TEXT NOT NULL CHECK(conflict_role IN ('claim_a','claim_b','supporting','contradicting','context')),
        PRIMARY KEY(conflict_id, assertion_id),
        FOREIGN KEY(conflict_id) REFERENCES kb_assertion_conflicts(conflict_id) ON DELETE CASCADE,
        FOREIGN KEY(assertion_id) REFERENCES kb_assertions(assertion_id)
    );

CREATE TABLE IF NOT EXISTS kb_conflict_resolutions(
        resolution_id TEXT PRIMARY KEY,
        conflict_id TEXT NOT NULL,
        decision TEXT NOT NULL,
        rationale TEXT NOT NULL,
        selected_assertion_id TEXT,
        resolution_evidence_id TEXT,
        resolved_by TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(conflict_id) REFERENCES kb_assertion_conflicts(conflict_id),
        FOREIGN KEY(selected_assertion_id) REFERENCES kb_assertions(assertion_id),
        FOREIGN KEY(resolution_evidence_id) REFERENCES kb_evidence_fragments(evidence_id),
        FOREIGN KEY(resolved_by) REFERENCES kb_actors(actor_id)
    );

CREATE TABLE IF NOT EXISTS kb_annotation_tasks(
        annotation_task_id TEXT PRIMARY KEY,
        record_id TEXT NOT NULL,
        task_type TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('open','assigned','in_progress','completed','blocked','cancelled')),
        priority INTEGER NOT NULL DEFAULT 0,
        assigned_to TEXT,
        due_at TEXT,
        instructions_json TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(record_id) REFERENCES kb_records(record_id),
        FOREIGN KEY(assigned_to) REFERENCES kb_actors(actor_id)
    );

CREATE TABLE IF NOT EXISTS kb_annotation_decisions(
        annotation_decision_id TEXT PRIMARY KEY,
        annotation_task_id TEXT NOT NULL,
        record_id TEXT NOT NULL,
        field_path TEXT NOT NULL,
        old_value_json TEXT,
        new_value_json TEXT NOT NULL,
        decision TEXT NOT NULL CHECK(decision IN ('accept','reject','revise','defer','unknown')),
        rationale TEXT NOT NULL,
        evidence_ids_json TEXT NOT NULL DEFAULT '[]',
        decided_by TEXT NOT NULL,
        decided_at TEXT NOT NULL,
        FOREIGN KEY(annotation_task_id) REFERENCES kb_annotation_tasks(annotation_task_id),
        FOREIGN KEY(record_id) REFERENCES kb_records(record_id),
        FOREIGN KEY(decided_by) REFERENCES kb_actors(actor_id)
    );

CREATE TABLE IF NOT EXISTS kb_annotation_rechecks(
        recheck_id TEXT PRIMARY KEY,
        record_id TEXT NOT NULL,
        original_decision_id TEXT,
        recheck_type TEXT NOT NULL CHECK(recheck_type IN ('delayed_blind','targeted','post_update','quality_sample')),
        agreement_status TEXT NOT NULL CHECK(agreement_status IN ('agree','partial','disagree','not_comparable')),
        original_value_json TEXT,
        recheck_value_json TEXT,
        notes TEXT,
        rechecked_by TEXT NOT NULL,
        rechecked_at TEXT NOT NULL,
        FOREIGN KEY(record_id) REFERENCES kb_records(record_id),
        FOREIGN KEY(original_decision_id) REFERENCES kb_annotation_decisions(annotation_decision_id),
        FOREIGN KEY(rechecked_by) REFERENCES kb_actors(actor_id)
    );

CREATE TABLE IF NOT EXISTS kb_gold_admission_reviews(
        gold_review_id TEXT PRIMARY KEY,
        record_id TEXT NOT NULL,
        validator_version TEXT NOT NULL,
        eligible INTEGER NOT NULL CHECK(eligible IN (0,1)),
        automatic_report_json TEXT NOT NULL,
        human_decision TEXT NOT NULL CHECK(human_decision IN ('pending','approve','reject','needs_revision')),
        decision_rationale TEXT,
        reviewed_by TEXT,
        reviewed_at TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(record_id) REFERENCES kb_records(record_id),
        FOREIGN KEY(reviewed_by) REFERENCES kb_actors(actor_id)
    );

CREATE TABLE IF NOT EXISTS kb_environments(
        environment_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        environment_type TEXT NOT NULL DEFAULT 'profile' CHECK(environment_type IN ('profile','baseline','vulnerable','fixed','negative','unknown')),
        architecture TEXT NOT NULL,
        runtime TEXT NOT NULL,
        description TEXT,
        facts_json TEXT NOT NULL,
        metadata_json TEXT NOT NULL,
        content_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

CREATE TABLE IF NOT EXISTS kb_environment_snapshots(
        environment_snapshot_id TEXT PRIMARY KEY,
        environment_id TEXT NOT NULL,
        parent_snapshot_id TEXT,
        snapshot_role TEXT NOT NULL DEFAULT 'observed' CHECK(snapshot_role IN ('observed','vulnerable','fixed','negative','unknown','baseline')),
        manifest_json TEXT NOT NULL,
        content_hash TEXT NOT NULL,
        collector_name TEXT,
        collector_version TEXT,
        captured_by TEXT,
        captured_at TEXT NOT NULL,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        UNIQUE(environment_id, content_hash),
        FOREIGN KEY(environment_id) REFERENCES kb_environments(environment_id),
        FOREIGN KEY(parent_snapshot_id) REFERENCES kb_environment_snapshots(environment_snapshot_id),
        FOREIGN KEY(captured_by) REFERENCES kb_actors(actor_id)
    );

CREATE TABLE IF NOT EXISTS kb_environment_facts(
        environment_fact_id TEXT PRIMARY KEY,
        environment_snapshot_id TEXT NOT NULL,
        fact_path TEXT NOT NULL,
        value_json TEXT,
        value_type TEXT NOT NULL,
        truth_state TEXT NOT NULL DEFAULT 'known' CHECK(truth_state IN ('known','unknown','not_applicable','conflicted')),
        collection_method TEXT NOT NULL,
        source_evidence_id TEXT,
        confidence_status TEXT NOT NULL DEFAULT 'unknown',
        observed_at TEXT,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        UNIQUE(environment_snapshot_id, fact_path),
        FOREIGN KEY(environment_snapshot_id) REFERENCES kb_environment_snapshots(environment_snapshot_id) ON DELETE CASCADE,
        FOREIGN KEY(source_evidence_id) REFERENCES kb_evidence_fragments(evidence_id)
    );

CREATE TABLE IF NOT EXISTS kb_environment_relations(
        environment_relation_id TEXT PRIMARY KEY,
        source_environment_id TEXT NOT NULL,
        target_environment_id TEXT NOT NULL,
        relation_type TEXT NOT NULL CHECK(relation_type IN ('contains','runs_on','derived_from','fixed_variant_of','negative_variant_of','equivalent_to')),
        metadata_json TEXT NOT NULL DEFAULT '{}',
        UNIQUE(source_environment_id, target_environment_id, relation_type),
        FOREIGN KEY(source_environment_id) REFERENCES kb_environments(environment_id),
        FOREIGN KEY(target_environment_id) REFERENCES kb_environments(environment_id)
    );

CREATE TABLE IF NOT EXISTS kb_rules(
        rule_id TEXT NOT NULL,
        version TEXT NOT NULL,
        record_id TEXT NOT NULL,
        rule_type TEXT NOT NULL DEFAULT 'exploitability' CHECK(rule_type IN ('exploitability','blocking','detection','mitigation','business_regression')),
        status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','verified','deprecated')),
        logic_version TEXT NOT NULL DEFAULT '1.0',
        expression_json TEXT NOT NULL,
        evidence_ids_json TEXT NOT NULL,
        description_zh TEXT,
        description_en TEXT,
        content_hash TEXT NOT NULL,
        created_by TEXT,
        created_at TEXT NOT NULL,
        supersedes_version TEXT,
        PRIMARY KEY(rule_id, version),
        FOREIGN KEY(record_id) REFERENCES kb_records(record_id),
        FOREIGN KEY(created_by) REFERENCES kb_actors(actor_id)
    );

CREATE TABLE IF NOT EXISTS kb_rule_evidence(
        rule_id TEXT NOT NULL,
        rule_version TEXT NOT NULL,
        evidence_id TEXT NOT NULL,
        support_type TEXT NOT NULL DEFAULT 'supports',
        notes TEXT,
        PRIMARY KEY(rule_id, rule_version, evidence_id),
        FOREIGN KEY(rule_id, rule_version) REFERENCES kb_rules(rule_id, version) ON DELETE CASCADE,
        FOREIGN KEY(evidence_id) REFERENCES kb_evidence_fragments(evidence_id)
    );

CREATE TABLE IF NOT EXISTS kb_rule_evaluations(
        evaluation_id TEXT PRIMARY KEY,
        rule_id TEXT NOT NULL,
        rule_version TEXT NOT NULL,
        environment_id TEXT NOT NULL,
        environment_snapshot_id TEXT,
        result TEXT NOT NULL CHECK(result IN ('true','false','unknown')),
        trace_json TEXT NOT NULL,
        evaluator_version TEXT NOT NULL,
        input_hash TEXT NOT NULL,
        error_json TEXT NOT NULL DEFAULT '{}',
        evaluated_at TEXT NOT NULL,
        FOREIGN KEY(rule_id, rule_version) REFERENCES kb_rules(rule_id, version),
        FOREIGN KEY(environment_id) REFERENCES kb_environments(environment_id),
        FOREIGN KEY(environment_snapshot_id) REFERENCES kb_environment_snapshots(environment_snapshot_id)
    );

CREATE TABLE IF NOT EXISTS kb_exploitability_assessments(
        assessment_id TEXT PRIMARY KEY,
        record_id TEXT NOT NULL,
        environment_snapshot_id TEXT NOT NULL,
        condition_state TEXT NOT NULL CHECK(condition_state IN ('satisfied','not_satisfied','unknown','conflicted')),
        reachability_state TEXT NOT NULL CHECK(reachability_state IN ('reachable','blocked','unknown')),
        chain_state TEXT NOT NULL CHECK(chain_state IN ('complete','incomplete','unknown')),
        validation_state TEXT NOT NULL CHECK(validation_state IN ('unverified','environment_verified','dynamically_verified','fully_reproduced','blocked_after_fix')),
        final_label TEXT NOT NULL CHECK(final_label IN ('verified_exploitable','verified_blocked','conditions_satisfied_unverified','chain_incomplete','conditions_not_satisfied','insufficient_evidence')),
        confidence_status TEXT NOT NULL,
        rationale TEXT NOT NULL,
        model_assisted INTEGER NOT NULL DEFAULT 0 CHECK(model_assisted IN (0,1)),
        assessed_by TEXT NOT NULL,
        assessed_at TEXT NOT NULL,
        supersedes_assessment_id TEXT,
        FOREIGN KEY(record_id) REFERENCES kb_records(record_id),
        FOREIGN KEY(environment_snapshot_id) REFERENCES kb_environment_snapshots(environment_snapshot_id),
        FOREIGN KEY(assessed_by) REFERENCES kb_actors(actor_id),
        FOREIGN KEY(supersedes_assessment_id) REFERENCES kb_exploitability_assessments(assessment_id)
    );

CREATE TABLE IF NOT EXISTS kb_assessment_inputs(
        assessment_id TEXT NOT NULL,
        input_type TEXT NOT NULL CHECK(input_type IN ('rule_evaluation','experiment','assertion','attack_chain','evidence','mitigation')),
        reference_id TEXT NOT NULL,
        input_role TEXT NOT NULL DEFAULT 'supporting',
        notes TEXT,
        PRIMARY KEY(assessment_id, input_type, reference_id),
        FOREIGN KEY(assessment_id) REFERENCES kb_exploitability_assessments(assessment_id) ON DELETE CASCADE
    );

CREATE TABLE IF NOT EXISTS kb_attack_chains(
        attack_chain_id TEXT PRIMARY KEY,
        name_en TEXT NOT NULL,
        name_zh TEXT,
        description TEXT,
        status TEXT NOT NULL CHECK(status IN ('candidate','verified','gold','deprecated')),
        initial_access TEXT,
        target_asset TEXT,
        final_impact TEXT,
        confidence_status TEXT NOT NULL DEFAULT 'unknown',
        created_by TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        FOREIGN KEY(created_by) REFERENCES kb_actors(actor_id)
    );

CREATE TABLE IF NOT EXISTS kb_attack_steps(
        attack_step_id TEXT PRIMARY KEY,
        attack_chain_id TEXT NOT NULL,
        step_order INTEGER,
        step_type TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        actor_state_before TEXT,
        action TEXT NOT NULL,
        capability_gained TEXT,
        boundary_crossed TEXT,
        actor_state_after TEXT,
        verification_status TEXT NOT NULL DEFAULT 'unknown',
        metadata_json TEXT NOT NULL DEFAULT '{}',
        FOREIGN KEY(attack_chain_id) REFERENCES kb_attack_chains(attack_chain_id) ON DELETE CASCADE
    );

CREATE TABLE IF NOT EXISTS kb_attack_edges(
        attack_edge_id TEXT PRIMARY KEY,
        attack_chain_id TEXT NOT NULL,
        source_step_id TEXT NOT NULL,
        target_step_id TEXT NOT NULL,
        relation_type TEXT NOT NULL CHECK(relation_type IN ('enables','requires','leads_to','alternative_to','blocks','observed_after')),
        condition_rule_id TEXT,
        condition_rule_version TEXT,
        probability REAL CHECK(probability IS NULL OR (probability >= 0 AND probability <= 1)),
        metadata_json TEXT NOT NULL DEFAULT '{}',
        UNIQUE(attack_chain_id, source_step_id, target_step_id, relation_type),
        FOREIGN KEY(attack_chain_id) REFERENCES kb_attack_chains(attack_chain_id) ON DELETE CASCADE,
        FOREIGN KEY(source_step_id) REFERENCES kb_attack_steps(attack_step_id),
        FOREIGN KEY(target_step_id) REFERENCES kb_attack_steps(attack_step_id),
        FOREIGN KEY(condition_rule_id, condition_rule_version) REFERENCES kb_rules(rule_id, version)
    );

CREATE TABLE IF NOT EXISTS kb_attack_step_records(
        attack_step_id TEXT NOT NULL,
        record_id TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('exploits','requires','triggered_by','amplified_by','results_in','context')),
        PRIMARY KEY(attack_step_id, record_id, role),
        FOREIGN KEY(attack_step_id) REFERENCES kb_attack_steps(attack_step_id) ON DELETE CASCADE,
        FOREIGN KEY(record_id) REFERENCES kb_records(record_id)
    );

CREATE TABLE IF NOT EXISTS kb_attack_step_conditions(
        attack_step_condition_id TEXT PRIMARY KEY,
        attack_step_id TEXT NOT NULL,
        condition_type TEXT NOT NULL CHECK(condition_type IN ('precondition','postcondition','blocking_condition','invariant')),
        rule_id TEXT,
        rule_version TEXT,
        assertion_id TEXT,
        description TEXT NOT NULL,
        FOREIGN KEY(attack_step_id) REFERENCES kb_attack_steps(attack_step_id) ON DELETE CASCADE,
        FOREIGN KEY(rule_id, rule_version) REFERENCES kb_rules(rule_id, version),
        FOREIGN KEY(assertion_id) REFERENCES kb_assertions(assertion_id)
    );

CREATE TABLE IF NOT EXISTS kb_experiment_protocols(
        protocol_id TEXT NOT NULL,
        version TEXT NOT NULL,
        name TEXT NOT NULL,
        objective TEXT NOT NULL,
        safety_level TEXT NOT NULL CHECK(safety_level IN ('V1','V2','V3','V4')),
        procedure_json TEXT NOT NULL,
        success_criteria_json TEXT NOT NULL,
        failure_criteria_json TEXT NOT NULL,
        rollback_json TEXT NOT NULL DEFAULT '{}',
        content_hash TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','approved','deprecated')),
        approved_by TEXT,
        created_at TEXT NOT NULL,
        PRIMARY KEY(protocol_id, version),
        FOREIGN KEY(approved_by) REFERENCES kb_actors(actor_id)
    );

CREATE TABLE IF NOT EXISTS kb_experiment_campaigns(
        campaign_id TEXT PRIMARY KEY,
        record_id TEXT NOT NULL,
        name TEXT NOT NULL,
        objective TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('planned','running','completed','partial','failed','cancelled')),
        created_by TEXT,
        started_at TEXT,
        finished_at TEXT,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        FOREIGN KEY(record_id) REFERENCES kb_records(record_id),
        FOREIGN KEY(created_by) REFERENCES kb_actors(actor_id)
    );

CREATE TABLE IF NOT EXISTS kb_experiments(
        experiment_id TEXT PRIMARY KEY,
        record_id TEXT NOT NULL,
        environment_id TEXT NOT NULL,
        environment_snapshot_id TEXT,
        campaign_id TEXT,
        protocol_id TEXT,
        protocol_version_ref TEXT,
        validation_level TEXT NOT NULL,
        outcome TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'completed' CHECK(status IN ('planned','running','completed','failed','cancelled')),
        repeat_index INTEGER NOT NULL DEFAULT 1 CHECK(repeat_index >= 1),
        protocol_version TEXT NOT NULL,
        artifacts_json TEXT NOT NULL,
        observations_json TEXT NOT NULL,
        executed_by TEXT NOT NULL,
        started_at TEXT,
        executed_at TEXT NOT NULL,
        finished_at TEXT,
        FOREIGN KEY(record_id) REFERENCES kb_records(record_id),
        FOREIGN KEY(environment_id) REFERENCES kb_environments(environment_id),
        FOREIGN KEY(environment_snapshot_id) REFERENCES kb_environment_snapshots(environment_snapshot_id),
        FOREIGN KEY(campaign_id) REFERENCES kb_experiment_campaigns(campaign_id),
        FOREIGN KEY(protocol_id, protocol_version_ref) REFERENCES kb_experiment_protocols(protocol_id, version)
    );

CREATE TABLE IF NOT EXISTS kb_experiment_steps(
        experiment_step_id TEXT PRIMARY KEY,
        experiment_id TEXT NOT NULL,
        step_no INTEGER NOT NULL,
        action_type TEXT NOT NULL,
        command_redacted TEXT,
        expected_result TEXT,
        actual_result TEXT,
        status TEXT NOT NULL CHECK(status IN ('planned','passed','failed','skipped','blocked','error')),
        started_at TEXT,
        finished_at TEXT,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        UNIQUE(experiment_id, step_no),
        FOREIGN KEY(experiment_id) REFERENCES kb_experiments(experiment_id) ON DELETE CASCADE
    );

CREATE TABLE IF NOT EXISTS kb_experiment_artifacts(
        experiment_artifact_id TEXT PRIMARY KEY,
        experiment_id TEXT NOT NULL,
        artifact_type TEXT NOT NULL,
        storage_path TEXT NOT NULL,
        content_hash TEXT NOT NULL,
        media_type TEXT,
        size_bytes INTEGER,
        redaction_status TEXT NOT NULL DEFAULT 'not_reviewed' CHECK(redaction_status IN ('not_reviewed','safe','redacted','restricted')),
        publication_status TEXT NOT NULL DEFAULT 'internal' CHECK(publication_status IN ('internal','embargoed','public','never_publish')),
        collected_at TEXT NOT NULL,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        UNIQUE(experiment_id, content_hash, artifact_type),
        FOREIGN KEY(experiment_id) REFERENCES kb_experiments(experiment_id) ON DELETE CASCADE
    );

CREATE TABLE IF NOT EXISTS kb_experiment_observations(
        experiment_observation_id TEXT PRIMARY KEY,
        experiment_id TEXT NOT NULL,
        observation_type TEXT NOT NULL,
        metric_name TEXT,
        value_json TEXT NOT NULL,
        unit TEXT,
        truth_state TEXT NOT NULL DEFAULT 'known' CHECK(truth_state IN ('known','unknown','conflicted')),
        observed_at TEXT NOT NULL,
        evidence_artifact_id TEXT,
        notes TEXT,
        FOREIGN KEY(experiment_id) REFERENCES kb_experiments(experiment_id) ON DELETE CASCADE,
        FOREIGN KEY(evidence_artifact_id) REFERENCES kb_experiment_artifacts(experiment_artifact_id)
    );

CREATE TABLE IF NOT EXISTS kb_mitigations(
        mitigation_id TEXT PRIMARY KEY,
        name_en TEXT NOT NULL,
        name_zh TEXT,
        mitigation_type TEXT NOT NULL CHECK(mitigation_type IN ('patch','upgrade','configuration','policy','isolation','detection','compensating_control')),
        description TEXT NOT NULL,
        scope TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('candidate','verified','recommended','deprecated')),
        side_effects_json TEXT NOT NULL DEFAULT '[]',
        prerequisites_json TEXT NOT NULL DEFAULT '[]',
        created_by TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(created_by) REFERENCES kb_actors(actor_id)
    );

CREATE TABLE IF NOT EXISTS kb_mitigation_targets(
        mitigation_target_id TEXT PRIMARY KEY,
        mitigation_id TEXT NOT NULL,
        target_type TEXT NOT NULL CHECK(target_type IN ('record','attack_chain','attack_step','rule','component')),
        target_id TEXT NOT NULL,
        effect_type TEXT NOT NULL CHECK(effect_type IN ('blocks','reduces','detects','removes_condition','contains','repairs')),
        effectiveness_status TEXT NOT NULL DEFAULT 'unknown',
        assertion_id TEXT,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        UNIQUE(mitigation_id, target_type, target_id, effect_type),
        FOREIGN KEY(mitigation_id) REFERENCES kb_mitigations(mitigation_id) ON DELETE CASCADE,
        FOREIGN KEY(assertion_id) REFERENCES kb_assertions(assertion_id)
    );

CREATE TABLE IF NOT EXISTS kb_mitigation_evidence(
        mitigation_id TEXT NOT NULL,
        evidence_id TEXT NOT NULL,
        support_type TEXT NOT NULL DEFAULT 'supports',
        PRIMARY KEY(mitigation_id, evidence_id),
        FOREIGN KEY(mitigation_id) REFERENCES kb_mitigations(mitigation_id) ON DELETE CASCADE,
        FOREIGN KEY(evidence_id) REFERENCES kb_evidence_fragments(evidence_id)
    );

CREATE TABLE IF NOT EXISTS kb_defense_policies(
        defense_policy_id TEXT NOT NULL,
        version TEXT NOT NULL,
        name TEXT NOT NULL,
        policy_type TEXT NOT NULL CHECK(policy_type IN ('seccomp','apparmor','selinux','rego','rbac','network_policy','runtime_config','admission_policy','other')),
        content_path TEXT,
        content_hash TEXT NOT NULL,
        generated_by TEXT,
        generated_by_model INTEGER NOT NULL DEFAULT 0 CHECK(generated_by_model IN (0,1)),
        status TEXT NOT NULL CHECK(status IN ('draft','validated','approved','deprecated')),
        created_at TEXT NOT NULL,
        PRIMARY KEY(defense_policy_id, version),
        FOREIGN KEY(generated_by) REFERENCES kb_actors(actor_id)
    );

CREATE TABLE IF NOT EXISTS kb_policy_validations(
        policy_validation_id TEXT PRIMARY KEY,
        defense_policy_id TEXT NOT NULL,
        defense_policy_version TEXT NOT NULL,
        environment_snapshot_id TEXT NOT NULL,
        security_result TEXT NOT NULL CHECK(security_result IN ('pass','fail','partial','unknown')),
        business_result TEXT NOT NULL CHECK(business_result IN ('pass','fail','partial','unknown')),
        experiment_id TEXT,
        notes TEXT,
        validated_at TEXT NOT NULL,
        FOREIGN KEY(defense_policy_id, defense_policy_version) REFERENCES kb_defense_policies(defense_policy_id, version),
        FOREIGN KEY(environment_snapshot_id) REFERENCES kb_environment_snapshots(environment_snapshot_id),
        FOREIGN KEY(experiment_id) REFERENCES kb_experiments(experiment_id)
    );

CREATE TABLE IF NOT EXISTS kb_repair_actions(
        repair_action_id TEXT PRIMARY KEY,
        record_id TEXT NOT NULL,
        mitigation_id TEXT,
        action_type TEXT NOT NULL CHECK(action_type IN ('upgrade','patch','configuration_change','policy_apply','rollback','manual_instruction')),
        action_json TEXT NOT NULL,
        precondition_rule_id TEXT,
        precondition_rule_version TEXT,
        rollback_json TEXT NOT NULL DEFAULT '{}',
        risk_level TEXT NOT NULL CHECK(risk_level IN ('low','medium','high','critical')),
        approval_status TEXT NOT NULL DEFAULT 'pending' CHECK(approval_status IN ('pending','approved','rejected','executed','rolled_back')),
        approved_by TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(record_id) REFERENCES kb_records(record_id),
        FOREIGN KEY(mitigation_id) REFERENCES kb_mitigations(mitigation_id),
        FOREIGN KEY(precondition_rule_id, precondition_rule_version) REFERENCES kb_rules(rule_id, version),
        FOREIGN KEY(approved_by) REFERENCES kb_actors(actor_id)
    );

CREATE TABLE IF NOT EXISTS kb_retest_runs(
        retest_run_id TEXT PRIMARY KEY,
        record_id TEXT NOT NULL,
        repair_action_id TEXT,
        before_environment_snapshot_id TEXT NOT NULL,
        after_environment_snapshot_id TEXT NOT NULL,
        security_outcome TEXT NOT NULL CHECK(security_outcome IN ('blocked','still_exploitable','inconclusive','error')),
        business_outcome TEXT NOT NULL CHECK(business_outcome IN ('pass','fail','partial','not_tested')),
        experiment_id TEXT,
        executed_by TEXT NOT NULL,
        executed_at TEXT NOT NULL,
        notes TEXT,
        FOREIGN KEY(record_id) REFERENCES kb_records(record_id),
        FOREIGN KEY(repair_action_id) REFERENCES kb_repair_actions(repair_action_id),
        FOREIGN KEY(before_environment_snapshot_id) REFERENCES kb_environment_snapshots(environment_snapshot_id),
        FOREIGN KEY(after_environment_snapshot_id) REFERENCES kb_environment_snapshots(environment_snapshot_id),
        FOREIGN KEY(experiment_id) REFERENCES kb_experiments(experiment_id),
        FOREIGN KEY(executed_by) REFERENCES kb_actors(actor_id)
    );

CREATE TABLE IF NOT EXISTS kb_retest_checks(
        retest_check_id TEXT PRIMARY KEY,
        retest_run_id TEXT NOT NULL,
        check_type TEXT NOT NULL CHECK(check_type IN ('security','business','performance','compatibility','rollback')),
        check_name TEXT NOT NULL,
        expected_json TEXT,
        actual_json TEXT,
        result TEXT NOT NULL CHECK(result IN ('pass','fail','partial','skipped','error')),
        artifact_id TEXT,
        notes TEXT,
        FOREIGN KEY(retest_run_id) REFERENCES kb_retest_runs(retest_run_id) ON DELETE CASCADE,
        FOREIGN KEY(artifact_id) REFERENCES kb_experiment_artifacts(experiment_artifact_id)
    );

CREATE TABLE IF NOT EXISTS kb_dataset_releases(
        release_id TEXT PRIMARY KEY,
        release_name TEXT NOT NULL DEFAULT 'container-security-kb',
        release_version TEXT,
        release_status TEXT NOT NULL DEFAULT 'draft' CHECK(release_status IN ('draft','frozen','published','withdrawn')),
        schema_version TEXT NOT NULL,
        taxonomy_version TEXT NOT NULL,
        released_at TEXT NOT NULL,
        released_by TEXT,
        manifest_json TEXT NOT NULL,
        content_hash TEXT,
        FOREIGN KEY(taxonomy_version) REFERENCES kb_taxonomy_versions(taxonomy_version),
        FOREIGN KEY(released_by) REFERENCES kb_actors(actor_id)
    );

CREATE TABLE IF NOT EXISTS kb_split_groups(
        split_group_id TEXT PRIMARY KEY,
        group_type TEXT NOT NULL CHECK(group_type IN ('vulnerability_family','patch_family','component_family','attack_pattern','duplicate_cluster','time_cohort')),
        group_key TEXT NOT NULL,
        description TEXT,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        UNIQUE(group_type, group_key)
    );

CREATE TABLE IF NOT EXISTS kb_split_group_members(
        split_group_id TEXT NOT NULL,
        record_id TEXT NOT NULL,
        membership_role TEXT NOT NULL DEFAULT 'member',
        PRIMARY KEY(split_group_id, record_id),
        FOREIGN KEY(split_group_id) REFERENCES kb_split_groups(split_group_id) ON DELETE CASCADE,
        FOREIGN KEY(record_id) REFERENCES kb_records(record_id)
    );

CREATE TABLE IF NOT EXISTS kb_dataset_memberships(
        release_id TEXT NOT NULL,
        record_id TEXT NOT NULL,
        split_name TEXT NOT NULL CHECK(split_name IN ('train','validation','test_id','test_ood','test_temporal','holdout','excluded')),
        family_group TEXT,
        split_group_id TEXT,
        inclusion_reason TEXT,
        record_content_hash TEXT,
        added_at TEXT,
        PRIMARY KEY(release_id, record_id),
        FOREIGN KEY(release_id) REFERENCES kb_dataset_releases(release_id),
        FOREIGN KEY(record_id) REFERENCES kb_records(record_id),
        FOREIGN KEY(split_group_id) REFERENCES kb_split_groups(split_group_id)
    );

CREATE TABLE IF NOT EXISTS kb_release_artifacts(
        release_artifact_id TEXT PRIMARY KEY,
        release_id TEXT NOT NULL,
        artifact_type TEXT NOT NULL,
        storage_path TEXT NOT NULL,
        content_hash TEXT NOT NULL,
        media_type TEXT,
        size_bytes INTEGER,
        publication_status TEXT NOT NULL DEFAULT 'internal',
        created_at TEXT NOT NULL,
        UNIQUE(release_id, artifact_type, content_hash),
        FOREIGN KEY(release_id) REFERENCES kb_dataset_releases(release_id) ON DELETE CASCADE
    );

CREATE TABLE IF NOT EXISTS kb_split_leakage_audits(
        leakage_audit_id TEXT PRIMARY KEY,
        release_id TEXT NOT NULL,
        audit_type TEXT NOT NULL CHECK(audit_type IN ('exact_duplicate','near_duplicate','family_overlap','component_overlap','temporal_leakage','source_overlap')),
        status TEXT NOT NULL CHECK(status IN ('running','passed','failed','review_required')),
        findings_json TEXT NOT NULL,
        tool_version TEXT NOT NULL,
        executed_at TEXT NOT NULL,
        FOREIGN KEY(release_id) REFERENCES kb_dataset_releases(release_id)
    );

CREATE TABLE IF NOT EXISTS kb_quality_check_runs(
        quality_run_id TEXT PRIMARY KEY,
        scope_type TEXT NOT NULL CHECK(scope_type IN ('database','record','release','taxonomy','experiment')),
        scope_id TEXT,
        check_suite_version TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('running','passed','failed','partial')),
        started_at TEXT NOT NULL,
        finished_at TEXT,
        summary_json TEXT NOT NULL DEFAULT '{}'
    );

CREATE TABLE IF NOT EXISTS kb_quality_check_results(
        quality_result_id TEXT PRIMARY KEY,
        quality_run_id TEXT NOT NULL,
        check_code TEXT NOT NULL,
        severity TEXT NOT NULL CHECK(severity IN ('info','warning','error','critical')),
        status TEXT NOT NULL CHECK(status IN ('pass','fail','skip','unknown')),
        object_type TEXT,
        object_id TEXT,
        message TEXT NOT NULL,
        details_json TEXT NOT NULL DEFAULT '{}',
        FOREIGN KEY(quality_run_id) REFERENCES kb_quality_check_runs(quality_run_id) ON DELETE CASCADE
    );

CREATE INDEX IF NOT EXISTS idx_kb_sources_type_level ON kb_sources(source_type, authority_level);

CREATE INDEX IF NOT EXISTS idx_kb_evidence_snapshot ON kb_evidence_fragments(snapshot_id);

CREATE INDEX IF NOT EXISTS idx_kb_conflicts_record_status ON kb_assertion_conflicts(record_id, status);

CREATE INDEX IF NOT EXISTS idx_kb_env_facts_path ON kb_environment_facts(fact_path);

CREATE INDEX IF NOT EXISTS idx_kb_rule_eval_rule_env ON kb_rule_evaluations(rule_id, rule_version, environment_id);

CREATE INDEX IF NOT EXISTS idx_kb_assessments_record_env ON kb_exploitability_assessments(record_id, environment_snapshot_id);

CREATE INDEX IF NOT EXISTS idx_kb_attack_steps_chain_order ON kb_attack_steps(attack_chain_id, step_order);

CREATE INDEX IF NOT EXISTS idx_kb_experiments_record_env ON kb_experiments(record_id, environment_id);

CREATE INDEX IF NOT EXISTS idx_kb_dataset_split ON kb_dataset_memberships(release_id, split_name);

CREATE INDEX IF NOT EXISTS idx_kb_audit_object ON kb_audit_events(object_type, object_id, occurred_at);

DROP VIEW IF EXISTS kb_v_unresolved_conflicts;

CREATE VIEW kb_v_unresolved_conflicts AS
    SELECT c.conflict_id, c.record_id, c.predicate, c.conflict_type, c.severity,
           c.status, c.summary, c.detected_at
    FROM kb_assertion_conflicts c
    WHERE c.status IN ('open','under_review');

DROP VIEW IF EXISTS kb_v_latest_environment_snapshots;

CREATE VIEW kb_v_latest_environment_snapshots AS
    SELECT s.*
    FROM kb_environment_snapshots s
    JOIN (
        SELECT environment_id, MAX(captured_at) AS max_captured_at
        FROM kb_environment_snapshots
        GROUP BY environment_id
    ) latest
      ON latest.environment_id=s.environment_id
     AND latest.max_captured_at=s.captured_at;

DROP VIEW IF EXISTS kb_v_record_evidence_coverage;

CREATE VIEW kb_v_record_evidence_coverage AS
    SELECT r.record_id,
           COUNT(DISTINCT a.assertion_id) AS assertion_count,
           COUNT(DISTINCT ae.evidence_id) AS evidence_count,
           COUNT(DISTINCT CASE WHEN e.evidence_level='E0' THEN e.evidence_id END) AS e0_count,
           COUNT(DISTINCT CASE WHEN e.evidence_level='E2' THEN e.evidence_id END) AS e2_count,
           COUNT(DISTINCT CASE WHEN e.evidence_level='E3' THEN e.evidence_id END) AS e3_count
    FROM kb_records r
    LEFT JOIN kb_assertions a ON a.record_id=r.record_id
    LEFT JOIN kb_assertion_evidence ae ON ae.assertion_id=a.assertion_id
    LEFT JOIN kb_evidence_fragments e ON e.evidence_id=ae.evidence_id
    GROUP BY r.record_id;

DROP VIEW IF EXISTS kb_v_gold_readiness;

CREATE VIEW kb_v_gold_readiness AS
    SELECT r.record_id, r.record_type, r.status, r.review_status,
           COALESCE(c.assertion_count,0) AS assertion_count,
           COALESCE(c.evidence_count,0) AS evidence_count,
           COALESCE(c.e0_count,0) AS e0_count,
           COALESCE(c.e2_count,0) AS e2_count,
           COALESCE(x.open_conflicts,0) AS open_conflicts,
           CASE
             WHEN r.generated_by_model=1 THEN 0
             WHEN COALESCE(x.open_conflicts,0)>0 THEN 0
             WHEN r.root_cause_l1 IS NULL OR r.root_cause_l1='' THEN 0
             WHEN r.root_cause_l2 IS NULL OR r.root_cause_l2='' THEN 0
             WHEN COALESCE(c.e0_count,0)=0 THEN 0
             ELSE 1
           END AS structurally_ready
    FROM kb_records r
    LEFT JOIN kb_v_record_evidence_coverage c ON c.record_id=r.record_id
    LEFT JOIN (
        SELECT record_id, COUNT(*) AS open_conflicts
        FROM kb_v_unresolved_conflicts
        GROUP BY record_id
    ) x ON x.record_id=r.record_id;

DROP TRIGGER IF EXISTS kb_trg_no_model_gold_insert;

CREATE TRIGGER kb_trg_no_model_gold_insert
    BEFORE INSERT ON kb_records
    WHEN NEW.status='gold' AND NEW.generated_by_model=1
    BEGIN
        SELECT RAISE(ABORT, 'model-generated record cannot be inserted as Gold');
    END;

DROP TRIGGER IF EXISTS kb_trg_no_model_gold_update;

CREATE TRIGGER kb_trg_no_model_gold_update
    BEFORE UPDATE OF status, generated_by_model ON kb_records
    WHEN NEW.status='gold' AND NEW.generated_by_model=1
    BEGIN
        SELECT RAISE(ABORT, 'model-generated record cannot be promoted to Gold');
    END;

DROP TRIGGER IF EXISTS kb_trg_source_snapshot_immutable_update;

CREATE TRIGGER kb_trg_source_snapshot_immutable_update
    BEFORE UPDATE ON kb_source_snapshots
    BEGIN
        SELECT RAISE(ABORT, 'source snapshots are immutable; create a new snapshot');
    END;

DROP TRIGGER IF EXISTS kb_trg_environment_snapshot_immutable_update;

CREATE TRIGGER kb_trg_environment_snapshot_immutable_update
    BEFORE UPDATE ON kb_environment_snapshots
    BEGIN
        SELECT RAISE(ABORT, 'environment snapshots are immutable; create a new snapshot');
    END;
