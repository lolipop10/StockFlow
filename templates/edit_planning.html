{% extends "base.html" %}

{% block title %}Modifier Planning - {{ company_name|default('Inventory Management') }}{% endblock %}

{% block content %}
<div class="container mt-4">
    <div class="row">
        <div class="col-12">
            <h2 class="mb-4">
                <i class="fas fa-edit"></i> Modifier le Planning d'Inventaire
            </h2>
        </div>
    </div>

    <div class="row">
        <div class="col-lg-8">
            <div class="card">
                <div class="card-header bg-warning">
                    <h5><i class="fas fa-wpforms"></i> Modification du Planning</h5>
                </div>
                <div class="card-body">
                    <form method="POST" action="{{ url_for('edit_planning', planning_id=planning.id) }}">
                        <!-- Date d'inventaire -->
                        <div class="mb-3">
                            <label for="date_inventaire" class="form-label">
                                <i class="fas fa-calendar"></i> Date d'Inventaire <span class="text-danger">*</span>
                            </label>
                            <input type="date" class="form-control" id="date_inventaire" 
                                   name="date_inventaire" value="{{ planning.date_inventaire }}" required>
                        </div>

                        <!-- Horaires -->
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label for="horaire_debut" class="form-label">
                                    <i class="fas fa-clock"></i> Heure de Début <span class="text-danger">*</span>
                                </label>
                                <input type="time" class="form-control" id="horaire_debut" 
                                       name="horaire_debut" value="{{ planning.horaire_debut }}" required>
                            </div>
                            <div class="col-md-6 mb-3">
                                <label for="horaire_fin" class="form-label">
                                    <i class="fas fa-clock"></i> Heure de Fin <span class="text-danger">*</span>
                                </label>
                                <input type="time" class="form-control" id="horaire_fin" 
                                       name="horaire_fin" value="{{ planning.horaire_fin }}" required>
                            </div>
                        </div>

                        <!-- Membres de l'équipe -->
                        <div class="mb-3">
                            <label for="equipe_membres" class="form-label">
                                <i class="fas fa-users"></i> Membres de l'Équipe <span class="text-danger">*</span>
                            </label>
                            <textarea class="form-control" id="equipe_membres" name="equipe_membres" 
                                      rows="3" required>{{ planning.equipe_membres }}</textarea>
                            <div class="form-text">Séparez les membres par des virgules</div>
                        </div>

                        <!-- Zones à inventorier -->
                        <div class="mb-3">
                            <label for="zones" class="form-label">
                                <i class="fas fa-map-marked-alt"></i> Zones à Inventorier <span class="text-danger">*</span>
                            </label>
                            <textarea class="form-control" id="zones" name="zones" 
                                      rows="3" required>{{ planning.zones }}</textarea>
                            <div class="form-text">Séparez les zones par des virgules</div>
                        </div>

                        <!-- Contrôleurs -->
                        <div class="mb-3">
                            <label for="controleurs" class="form-label">
                                <i class="fas fa-user-check"></i> Contrôleurs
                            </label>
                            <input type="text" class="form-control" id="controleurs" 
                                   name="controleurs" value="{{ planning.controleurs or '' }}">
                            <div class="form-text">Séparez les contrôleurs par des virgules (optionnel)</div>
                        </div>

                        <!-- Remarques -->
                        <div class="mb-4">
                            <label for="remarques" class="form-label">
                                <i class="fas fa-comment"></i> Remarques
                            </label>
                            <textarea class="form-control" id="remarques" name="remarques" 
                                      rows="3">{{ planning.remarques or '' }}</textarea>
                        </div>

                        <!-- Boutons d'action -->
                        <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                            <button type="submit" class="btn btn-warning btn-lg">
                                <i class="fas fa-save"></i> Enregistrer les Modifications
                            </button>
                            <a href="{{ url_for('planning') }}" class="btn btn-secondary btn-lg">
                                <i class="fas fa-times"></i> Annuler
                            </a>
                        </div>
                    </form>
                </div>
            </div>
        </div>

        <!-- Panneau d'information -->
        <div class="col-lg-4">
            <div class="card border-info">
                <div class="card-header bg-info text-white">
                    <h5><i class="fas fa-info-circle"></i> Informations</h5>
                </div>
                <div class="card-body">
                    <p class="small"><strong>Planning ID:</strong> #{{ planning.id }}</p>
                    <p class="small"><strong>Date actuelle:</strong> {{ planning.date_inventaire }}</p>
                    <hr>
                    <p class="small text-muted mb-0">
                        <i class="fas fa-exclamation-circle"></i> 
                        Les modifications seront visibles par tous les utilisateurs immédiatement.
                    </p>
                </div>
            </div>

            <div class="card mt-3 border-warning">
                <div class="card-header bg-warning">
                    <h6 class="mb-0"><i class="fas fa-exclamation-triangle"></i> Attention</h6>
                </div>
                <div class="card-body">
                    <ul class="small mb-0">
                        <li>Vérifiez que les membres sont disponibles</li>
                        <li>Assurez-vous de ne pas créer de conflits de zones</li>
                        <li>Les horaires doivent être cohérents</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
// Validation des horaires
document.querySelector('form').addEventListener('submit', function(e) {
    const debut = document.getElementById('horaire_debut').value;
    const fin = document.getElementById('horaire_fin').value;
    
    if (debut && fin && debut >= fin) {
        e.preventDefault();
        alert('L\'heure de fin doit être postérieure à l\'heure de début!');
        return false;
    }
});

// Animation sur le bouton de sauvegarde
document.querySelector('form').addEventListener('submit', function(e) {
    const submitBtn = this.querySelector('button[type="submit"]');
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Enregistrement...';
    submitBtn.disabled = true;
});
</script>
{% endblock %}