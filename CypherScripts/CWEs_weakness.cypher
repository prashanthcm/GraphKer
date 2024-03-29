// ------------------------------------------------------------------------
// Insert Weaknesses for CWEs
UNWIND [cweWeaknessFilesToImport] AS files
CALL apoc.periodic.iterate(
  'CALL apoc.load.json($files) YIELD value AS weakness RETURN weakness',
  '
    // Insert CWEs
    MERGE (w:CWE {
      Name: "CWE-" + weakness.ID
    })
    SET w.Extended_Name = weakness.Name,
      w.Abstraction = weakness.Abstraction,
      w.Structure = weakness.Structure,
      w.Status = weakness.Status,
      w.Description = weakness.Description,
      w.Likelihood_Of_Exploit = weakness.Likelihood_Of_Exploit,
      w.Modes_Of_Introduction = [value IN weakness.Modes_Of_Introduction.Introduction | value.Phase],
      w.Submission_Date = weakness.Content_History.Submission.Submission_Date,
      w.Submission_Name = weakness.Content_History.Submission.Submission_Name,
      w.Submission_Organization = weakness.Content_History.Submission.Submission_Organization,
      w.Affected_Resources = [value IN weakness.Affected_Resources.Affected_Resource | value],
      w.Functional_Areas = [value IN weakness.Functional_Areas.Functional_Area | value]

    // Insert Related Weaknesses CWE --> CWE
    WITH w, weakness
    FOREACH (Rel_Weakness IN weakness.Related_Weaknesses.Related_Weakness |
      MERGE (cwe:CWE {Name: "CWE-" + Rel_Weakness.CWE_ID})
      MERGE (w)-[:Related_Weakness {Nature: Rel_Weakness.Nature}]->(cwe)
    )

    // Insert Applicable Platforms for CWEs
    WITH w, weakness
    FOREACH (platform IN weakness.Applicable_Platforms |
      FOREACH (type IN ["Language", "Technology", "Architecture", "Operating System"] |
        FOREACH (data IN platform[type] |
          MERGE (ap:Applicable_Platform {Type: type, Prevalence: data.Prevalence,
            Name: coalesce(data.Name, "NOT SET"), Class: coalesce(data.Class, "NOT SET")})
          MERGE (w)-[:Applicable_Platform]->(ap)
        )
      )
    )


    // Insert Consequences for CWEs
    WITH w, weakness
    FOREACH (consequence IN weakness.Common_Consequences.Consequence |
      MERGE (con:Consequence {Scope: consequence.Scope})
      MERGE (w)-[rel:hasConsequence]->(con)
      SET rel.Impact = consequence.Impact,
      rel.Note = consequence.Note, rel.Likelihood = consequence.Likelihood
    )

    // Insert Detection Methods for CWEs
    WITH w, weakness
    FOREACH (dec IN weakness.Detection_Methods.Detection_Method |
      MERGE (d:Detection_Method {
        Method: dec.Method
      })
      MERGE (w)-[wd:canBeDetected]->(d)
      SET wd.Effectiveness = dec.Effectiveness,
      wd.Detection_Method_ID = dec.Detection_Method_ID
    )

    // Insert Related Attack Patterns - CAPEC for CWEs
    WITH w, weakness
    FOREACH (rap IN weakness.Related_Attack_Patterns.Related_Attack_Pattern |
      MERGE (cp:CAPEC {
        Name: "CAPEC-" + rap.CAPEC_ID
      })
      MERGE (w)-[:RelatedAttackPattern]->(cp)
    )

    // Public References for CWEs
    WITH w, weakness
    FOREACH (exReference IN weakness.References.Reference |
      MERGE (ref:External_Reference_CWE {Reference_ID: exReference.External_Reference_ID})
      MERGE (w)-[:hasExternal_Reference]->(ref)
    )
  ',
  {batchSize:200, params: {files:files}}
) YIELD batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics
RETURN batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics;
