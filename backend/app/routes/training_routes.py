"""Training Simulation Routes"""
from flask import Blueprint, request, jsonify
from app.models.training_simulation import SecuritySimulation, UserTrainingProgress

training_bp = Blueprint('training', __name__, url_prefix='/api/training')

@training_bp.route('/simulations', methods=['GET'])
def get_simulations():
    try:
        # Return sample simulations (would query from Firestore in production)
        simulations = [
            {
                'simulation_id': '1',
                'title': 'Phishing Email Detection',
                'type': 'phishing',
                'difficulty': 'beginner',
                'scenario': 'Identify suspicious emails',
                'points': 10,
                'steps': [
                    {
                        'title': 'Email Analysis',
                        'description': 'You receive an email claiming to be from IT support...',
                        'options': [
                            {'id': 'a', 'text': 'Click the link to verify'},
                            {'id': 'b', 'text': 'Report as phishing'},
                            {'id': 'c', 'text': 'Reply with credentials'}
                        ]
                    }
                ],
                'correct_actions': ['b']
            }
        ]
        
        return jsonify({'success': True, 'simulations': simulations}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@training_bp.route('/progress/<user_id>', methods=['GET'])
def get_progress(user_id):
    try:
        progress = UserTrainingProgress.get_by_user_id(user_id)
        return jsonify({'success': True, 'progress': progress.to_dict()}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@training_bp.route('/complete', methods=['POST'])
def complete_simulation():
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        simulation_id = data.get('simulation_id')
        score = data.get('score')
        
        progress = UserTrainingProgress.get_by_user_id(user_id)
        progress.completed_simulations.append(simulation_id)
        progress.security_awareness_score = (progress.security_awareness_score + score) / 2
        progress.save()
        
        return jsonify({'success': True, 'progress': progress.to_dict()}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
