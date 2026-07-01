package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type FieldDef struct {
	Key       string   `json:"key"`
	Label     string   `json:"label"`
	Type      string   `json:"type"`
	Required  bool     `json:"required,omitempty"`
	Help      string   `json:"help,omitempty"`
	MaxLength int      `json:"max_length,omitempty"`
	Options   []string `json:"options,omitempty"`
}

var allowedFieldTypes = map[string]bool{
	"text": true, "textarea": true, "email": true,
	"select": true, "radio": true, "number": true, "checkbox": true,
}

var (
	emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	keyRe   = regexp.MustCompile(`^[a-z0-9_]+$`)
)

type Form struct {
	ID            string     `json:"id"`
	Slug          string     `json:"slug"`
	Ref           string     `json:"ref"`
	Title         string     `json:"title"`
	Description   string     `json:"description,omitempty"`
	Fields        []FieldDef `json:"fields"`
	OwnerTeam     string     `json:"owner_team"`
	Status        string     `json:"status"`
	AllowMultiple bool       `json:"allow_multiple"`
	ExpiresAt     int64      `json:"expires_at,omitempty"`
	CreatedBy     string     `json:"created_by,omitempty"`
	CreatedAt     int64      `json:"created_at"`
}

func (f *Form) publicURL(base string) string { return base + "/f/" + f.Slug }

func (f *Form) resultsURL(base string) string { return base + "/surveys/" + f.Ref }

func (f *Form) isExpired() bool { return f.ExpiresAt != 0 && f.ExpiresAt < nowMs() }

func (f *Form) acceptsSubmissions() bool { return f.Status == "active" && !f.isExpired() }

type Submission struct {
	ID        string            `json:"id"`
	FormID    string            `json:"form_id"`
	Values    map[string]string `json:"values"`
	UserAgent string            `json:"user_agent,omitempty"`
	CreatedAt int64             `json:"created_at"`
}

func validateFieldDefs(fields []FieldDef) error {
	if len(fields) == 0 {
		return fmt.Errorf("a form needs at least one field")
	}
	seen := map[string]bool{}
	for i := range fields {
		f := &fields[i]
		if !keyRe.MatchString(f.Key) {
			return fmt.Errorf("field key %q must match [a-z0-9_]+", f.Key)
		}
		if seen[f.Key] {
			return fmt.Errorf("duplicate field key %q", f.Key)
		}
		seen[f.Key] = true
		if strings.TrimSpace(f.Label) == "" {
			return fmt.Errorf("field %q needs a label", f.Key)
		}
		if !allowedFieldTypes[f.Type] {
			return fmt.Errorf("field %q has unknown type %q", f.Key, f.Type)
		}
		if (f.Type == "select" || f.Type == "radio") && len(f.Options) == 0 {
			return fmt.Errorf("field %q (%s) needs options", f.Key, f.Type)
		}
	}
	return nil
}

func validateSubmission(form *Form, raw map[string]string) (map[string]string, map[string]string) {
	const hardMax = 10000
	out := map[string]string{}
	errs := map[string]string{}
	for i := range form.Fields {
		f := &form.Fields[i]
		v := strings.TrimSpace(raw[f.Key])
		if f.Type == "checkbox" {
			if v == "on" || v == "true" || v == "1" || v == "yes" {
				out[f.Key] = "true"
			} else {
				out[f.Key] = "false"
			}
			if f.Required && out[f.Key] != "true" {
				errs[f.Key] = fmt.Sprintf("%s ist erforderlich.", f.Label)
			}
			continue
		}
		if v == "" {
			if f.Required {
				errs[f.Key] = fmt.Sprintf("%s ist erforderlich.", f.Label)
			}
			continue
		}
		max := f.MaxLength
		if max <= 0 || max > hardMax {
			max = hardMax
		}
		if len([]rune(v)) > max {
			errs[f.Key] = fmt.Sprintf("%s ist zu lang (max. %d Zeichen).", f.Label, max)
			continue
		}
		switch f.Type {
		case "email":
			if !emailRe.MatchString(v) {
				errs[f.Key] = fmt.Sprintf("%s ist keine gültige E-Mail-Adresse.", f.Label)
				continue
			}
		case "number":
			if _, err := strconv.ParseFloat(v, 64); err != nil {
				errs[f.Key] = fmt.Sprintf("%s muss eine Zahl sein.", f.Label)
				continue
			}
		case "select", "radio":
			if !contains(f.Options, v) {
				errs[f.Key] = fmt.Sprintf("%s: ungültige Auswahl.", f.Label)
				continue
			}
		}
		out[f.Key] = v
	}
	return out, errs
}

type createFormInput struct {
	Title         string
	Description   string
	Ref           string
	Fields        []FieldDef
	OwnerTeam     string
	ExpiresAt     int64
	AllowMultiple bool
}

func (a *App) createForm(in createFormInput, createdBy string) (*Form, error) {
	if strings.TrimSpace(in.Title) == "" {
		return nil, fmt.Errorf("title is required")
	}
	if strings.TrimSpace(in.OwnerTeam) == "" {
		return nil, fmt.Errorf("owner_team is required")
	}
	if err := validateFieldDefs(in.Fields); err != nil {
		return nil, err
	}
	fieldsJSON, _ := json.Marshal(in.Fields)
	f := &Form{
		ID:            genID("form"),
		Title:         in.Title,
		Description:   in.Description,
		Fields:        in.Fields,
		OwnerTeam:     in.OwnerTeam,
		Status:        "active",
		AllowMultiple: in.AllowMultiple,
		ExpiresAt:     in.ExpiresAt,
		CreatedBy:     createdBy,
		CreatedAt:     nowMs(),
	}
	am := 0
	if f.AllowMultiple {
		am = 1
	}

	refBase := f.Title
	if strings.TrimSpace(in.Ref) != "" {
		refBase = in.Ref
	}

	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		f.Slug = randomSlug()
		f.Ref = a.db.uniqueRef(slugify(refBase), "")
		_, err := a.db.Exec(
			`INSERT INTO forms(id, slug, ref, title, description, fields, owner_team, status, allow_multiple, expires_at, created_by, created_at)
			 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
			f.ID, f.Slug, f.Ref, f.Title, nullStr(f.Description), string(fieldsJSON), f.OwnerTeam, f.Status, am, msPtr(f.ExpiresAt), nullStr(f.CreatedBy), f.CreatedAt,
		)
		if err == nil {
			return f, nil
		}
		lastErr = err
		if !strings.Contains(err.Error(), "UNIQUE") {
			return nil, err
		}
	}
	return nil, lastErr
}

func scanForm(s interface{ Scan(...any) error }) (*Form, error) {
	var (
		f                    Form
		ref, desc, createdBy sql.NullString
		fields               string
		am                   int
		expires              sql.NullInt64
	)
	if err := s.Scan(&f.ID, &f.Slug, &ref, &f.Title, &desc, &fields, &f.OwnerTeam, &f.Status, &am, &expires, &createdBy, &f.CreatedAt); err != nil {
		return nil, err
	}
	f.Ref, f.Description, f.CreatedBy = ref.String, desc.String, createdBy.String
	f.AllowMultiple = am != 0
	f.ExpiresAt = expires.Int64
	_ = json.Unmarshal([]byte(fields), &f.Fields)
	return &f, nil
}

const formCols = `id, slug, ref, title, description, fields, owner_team, status, allow_multiple, expires_at, created_by, created_at`

func (a *App) getFormByRef(ref string) (*Form, error) {
	row := a.db.QueryRow(`SELECT `+formCols+` FROM forms WHERE ref = ?`, ref)
	f, err := scanForm(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return f, err
}

func (a *App) getFormByID(id string) (*Form, error) {
	row := a.db.QueryRow(`SELECT `+formCols+` FROM forms WHERE id = ?`, id)
	f, err := scanForm(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return f, err
}

func (a *App) getFormBySlug(slug string) (*Form, error) {
	row := a.db.QueryRow(`SELECT `+formCols+` FROM forms WHERE slug = ?`, slug)
	f, err := scanForm(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return f, err
}

func (a *App) listFormsForTeams(teams []string) ([]*Form, error) {
	if len(teams) == 0 {
		return nil, nil
	}
	ph := make([]string, len(teams))
	args := make([]any, len(teams))
	for i, t := range teams {
		ph[i] = "?"
		args[i] = t
	}
	rows, err := a.db.Query(`SELECT `+formCols+` FROM forms WHERE owner_team IN (`+strings.Join(ph, ",")+`) ORDER BY created_at DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Form
	for rows.Next() {
		f, err := scanForm(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

type formPatch struct {
	Title       *string
	Description *string
	Ref         *string
	Status      *string
	ExpiresAt   *int64
	Fields      *[]FieldDef
}

func (a *App) updateForm(id string, p formPatch) (*Form, error) {
	f, err := a.getFormByID(id)
	if err != nil || f == nil {
		return nil, err
	}
	if p.Title != nil {
		f.Title = *p.Title
	}
	if p.Description != nil {
		f.Description = *p.Description
	}
	if p.Ref != nil {
		f.Ref = a.db.uniqueRef(slugify(*p.Ref), f.ID)
	}
	if p.Status != nil {
		if *p.Status != "active" && *p.Status != "disabled" {
			return nil, fmt.Errorf("status must be active or disabled")
		}
		f.Status = *p.Status
	}
	if p.ExpiresAt != nil {
		f.ExpiresAt = *p.ExpiresAt
	}
	if p.Fields != nil {
		if err := validateFieldDefs(*p.Fields); err != nil {
			return nil, err
		}
		f.Fields = *p.Fields
	}
	fieldsJSON, _ := json.Marshal(f.Fields)
	_, err = a.db.Exec(
		`UPDATE forms SET title=?, description=?, ref=?, status=?, expires_at=?, fields=? WHERE id=?`,
		f.Title, nullStr(f.Description), f.Ref, f.Status, msPtr(f.ExpiresAt), string(fieldsJSON), id,
	)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (a *App) deleteForm(id string) (bool, error) {
	res, err := a.db.Exec(`DELETE FROM forms WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (a *App) countSubmissions(formID string) (int, error) {
	var n int
	err := a.db.QueryRow(`SELECT COUNT(*) FROM submissions WHERE form_id = ?`, formID).Scan(&n)
	return n, err
}

func (a *App) insertSubmission(formID string, values map[string]string, ua, ipHash string) (*Submission, error) {
	valuesJSON, _ := json.Marshal(values)
	s := &Submission{ID: genID("sub"), FormID: formID, Values: values, CreatedAt: nowMs()}
	_, err := a.db.Exec(
		`INSERT INTO submissions(id, form_id, data, user_agent, ip_hash, created_at) VALUES (?,?,?,?,?,?)`,
		s.ID, formID, string(valuesJSON), nullStr(ua), nullStr(ipHash), s.CreatedAt,
	)
	return s, err
}

func (a *App) listSubmissions(formID string, since int64, limit, offset int) ([]*Submission, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	rows, err := a.db.Query(
		`SELECT id, form_id, data, user_agent, created_at FROM submissions
		 WHERE form_id = ? AND created_at > ? ORDER BY created_at ASC LIMIT ? OFFSET ?`,
		formID, since, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Submission
	for rows.Next() {
		var (
			s      Submission
			values string
			ua     sql.NullString
		)
		if err := rows.Scan(&s.ID, &s.FormID, &values, &ua, &s.CreatedAt); err != nil {
			return nil, err
		}
		s.UserAgent = ua.String
		_ = json.Unmarshal([]byte(values), &s.Values)
		out = append(out, &s)
	}
	return out, rows.Err()
}

func (a *App) submissionFormID(id string) (string, error) {
	var formID string
	err := a.db.QueryRow(`SELECT form_id FROM submissions WHERE id = ?`, id).Scan(&formID)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return formID, err
}

func (a *App) deleteSubmission(id string) (bool, error) {
	res, err := a.db.Exec(`DELETE FROM submissions WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
